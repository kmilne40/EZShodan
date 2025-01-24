import os
import shodan
import json
import logging
import curses
import curses.textpad
import re
import sys
import time

# -------------------- Configuration and Initialization -------------------- #

# Configure logging
logging.basicConfig(
    filename='shodan_tool.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Retrieve Shodan API key from environment variable
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    print("Error: Shodan API key not found. Please set the SHODAN_API_KEY environment variable.")
    sys.exit(1)

try:
    api = shodan.Shodan(SHODAN_API_KEY)
except shodan.APIError as e:
    print(f"Error initializing Shodan API: {e}")
    logging.error(f"Shodan API Initialization Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error initializing Shodan API: {e}")
    logging.error(f"Unexpected Shodan API Initialization Error: {e}")
    sys.exit(1)

# -------------------- Utility Functions -------------------- #

def is_valid_domain(domain):
    """
    Validates the domain format using regex.
    """
    domain_regex = re.compile(
        r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )
    return bool(domain_regex.match(domain))

def is_valid_cidr(network):
    """
    Validates the CIDR notation.
    """
    cidr_regex = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/(?:3[0-2]|[12]?\d)$"
    )
    return bool(cidr_regex.match(network))

# -------------------- Shodan Query Builder -------------------- #

class ShodanQueryBuilder:
    """
    Manages the base query and filters. Supports AND/OR logic.
    """
    def __init__(self):
        self.base_query = ""
        self.full_query = ""

    def set_base_query(self, base):
        self.base_query = base.strip()
        self.full_query = self.base_query

    def reset(self):
        self.base_query = ""
        self.full_query = ""

    def is_empty(self):
        return not self.full_query.strip()

    def add_filter(self, f, operator="AND"):
        """
        Add a filter with a specified operator (AND/OR).
        For AND: just append with a space.
        For OR: wrap existing query and new filter in parentheses and insert OR.
        """
        f = f.strip()
        if not f:
            return
        if self.is_empty():
            # If query empty, just start with this filter
            self.full_query = f
        else:
            if operator.upper() == "AND":
                self.full_query = f"{self.full_query} {f}"
            elif operator.upper() == "OR":
                self.full_query = f"({self.full_query}) OR ({f})"

    def get_query(self):
        # If no base and no filters, default to "*"
        if self.is_empty():
            return "*"
        return self.full_query.strip()

query_builder = ShodanQueryBuilder()
results_cache = []

# -------------------- Curses-Based UI Functions -------------------- #

def draw_menu(stdscr, selected_idx, menu_options):
    """
    Draws the main menu with color-coded options.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Draw a border
    stdscr.border(0)

    # Add header
    header = "===== KISS: Kev's Interactive Shodan Simplifier ====="
    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
    stdscr.addstr(1, width//2 - len(header)//2, header)
    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

    # Add menu items
    for idx, option in enumerate(menu_options):
        x = 4
        y = 3 + idx
        if idx == selected_idx:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, f"> {option}")
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, f"  {option}")
            stdscr.attroff(curses.color_pair(2))

    # Add footer
    footer = "Use Arrow Keys to Navigate and Enter to Select"
    stdscr.attron(curses.color_pair(4))
    stdscr.addstr(height-2, width//2 - len(footer)//2, footer)
    stdscr.attroff(curses.color_pair(4))

    stdscr.refresh()

def display_message(stdscr, message, color_pair):
    """
    Displays a centered message with a specified color pair.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.attron(curses.color_pair(color_pair))
    stdscr.addstr(height//2 - 1, width//2 - len(message)//2, message)
    stdscr.attroff(curses.color_pair(color_pair))
    stdscr.addstr(height//2 + 1, width//2 - len("Press any key to continue...")//2, "Press any key to continue...")
    stdscr.refresh()
    stdscr.getch()

def prompt_input(stdscr, prompt_str):
    """
    Prompts the user for input within curses.
    """
    curses.echo()
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(height//2 - 1, width//2 - len(prompt_str)//2, prompt_str)
    stdscr.refresh()
    input_str = stdscr.getstr(height//2, width//2 - 20, 40).decode().strip()
    curses.noecho()
    return input_str

def print_ascii_banner(stdscr):
    """
    Prints the ASCII banner at the top of the screen.
    """
    banner = [
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        "@@@@     K   I   S   S       @@@@",
        "@@@@                         @@@@",
        "@@@@   Kev's Interactive     @@@@",
        "@@@@   Shodan Simplifier     @@@@",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    ]
    height, width = stdscr.getmaxyx()
    for idx, line in enumerate(banner):
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(1 + idx, width//2 - len(line)//2, line)
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
    stdscr.refresh()

def main_menu(stdscr):
    """
    Main menu loop.
    """
    curses.curs_set(0)  # Hide cursor

    # Initialize color pairs
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)    # Selected Option
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)    # Normal Text
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLUE)    # Header
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)     # Footer
    curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)      # Error Messages
    curses.init_pair(6, curses.COLOR_GREEN, curses.COLOR_BLACK)    # Success Messages

    menu_options = [
        "1. Choose a target type (domain, organization, network, IP, or nothing)",
        "2. Add filters (port, vulnerabilities, etc.) with AND/OR",
        "3. Finalize query, edit manually if needed, and execute",
        "4. Save last results to file",
        "5. View and add trending CVE-based queries",
        "6. Manage Shodan Alerts",
        "7. View Stats/Facets for the current query",
        "8. Start a new clean query",
        "9. Exit"
    ]

    selected_idx = 0

    print_ascii_banner(stdscr)

    while True:
        draw_menu(stdscr, selected_idx, menu_options)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            # Execute the selected option
            execute_option(stdscr, selected_idx + 1)
        elif key in [ord('x'), ord('X')]:
            exit_program(stdscr)
        else:
            pass  # Ignore other keys

def execute_option(stdscr, option_num):
    """
    Executes the function corresponding to the selected menu option.
    """
    global results_cache
    # Removed config_data as load_config() is undefined and not used.

    if option_num == 1:
        choose_target_type(stdscr)
    elif option_num == 2:
        add_filters_menu(stdscr)
    elif option_num == 3:
        finalize_and_execute_query(stdscr)
    elif option_num == 4:
        save_results_to_file(stdscr)
    elif option_num == 5:
        add_trending_cve_filter(stdscr)
    elif option_num == 6:
        manage_alerts_menu(stdscr)
    elif option_num == 7:
        view_stats(stdscr)
    elif option_num == 8:
        start_new_query(stdscr)
    elif option_num == 9:
        exit_program(stdscr)
    else:
        display_message(stdscr, "Invalid option selected.", 5)

def choose_target_type(stdscr):
    """
    Allows the user to choose a target type and sets the base query accordingly.
    """
    menu_options = [
        "1. Domain (e.g., hostname:example.com)",
        "2. Organization (e.g., org:\"Google LLC\")",
        "3. Network (CIDR) (e.g., net:192.168.1.0/24)",
        "4. IP Address (e.g., 8.8.8.8)",
        "5. Nothing (empty base query)"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Choose Target Type", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                domain = prompt_input(stdscr, "Enter the domain (e.g., example.com): ")
                if is_valid_domain(domain):
                    query_builder.set_base_query(f"hostname:{domain}")
                    display_message(stdscr, f"Base query set to: hostname:{domain}", 6)
                else:
                    display_message(stdscr, f"Invalid domain format: {domain}", 5)
            elif choice == 2:
                org = prompt_input(stdscr, "Enter the organization name (e.g., Google LLC): ")
                if org:
                    query_builder.set_base_query(f'org:"{org}"')
                    display_message(stdscr, f'Base query set to: org:"{org}"', 6)
                else:
                    display_message(stdscr, "Organization name cannot be empty.", 5)
            elif choice == 3:
                network = prompt_input(stdscr, "Enter the network CIDR (e.g., 192.168.1.0/24): ")
                if is_valid_cidr(network):
                    query_builder.set_base_query(f"net:{network}")
                    display_message(stdscr, f"Base query set to: net:{network}", 6)
                else:
                    display_message(stdscr, f"Invalid CIDR format: {network}", 5)
            elif choice == 4:
                ip_address = prompt_input(stdscr, "Enter the IP address (e.g., 8.8.8.8): ")
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_address):
                    query_builder.set_base_query(ip_address)
                    display_message(stdscr, f"Base query set to: {ip_address}", 6)
                else:
                    display_message(stdscr, f"Invalid IP address format: {ip_address}", 5)
            elif choice == 5:
                query_builder.set_base_query("")
                display_message(stdscr, "Base query cleared.", 6)
            break
        elif key in [ord('q'), ord('Q')]:
            break

def add_filters_menu(stdscr):
    """
    Allows the user to add filters with AND/OR logic.
    """
    menu_options = [
        "1. Add port filter (e.g., port:22)",
        "2. Add vulnerability (e.g., vuln:CVE-2023-12345)",
        "3. Add key phrase (e.g., \"admin\")",
        "4. Add product (e.g., product:Apache)",
        "5. Add country (e.g., country:US)",
        "6. Add city (e.g., city:\"New York\")",
        "7. Add OS (e.g., os:\"Windows 10\")",
        "8. Add raw filter (expert mode)",
        "9. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Add Filters", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            operator = "AND"
            if choice != 9:
                operator = prompt_input(stdscr, "Combine this filter with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"

            if choice == 1:
                port = prompt_input(stdscr, "Enter the port number (e.g., 22): ")
                if port.isdigit():
                    query_builder.add_filter(f"port:{port}", operator=operator)
                    display_message(stdscr, f"Filter added: port:{port}", 6)
                else:
                    display_message(stdscr, f"Invalid port number: {port}", 5)
            elif choice == 2:
                vuln = prompt_input(stdscr, "Enter the CVE (e.g., CVE-2023-12345): ")
                if re.match(r"^CVE-\d{4}-\d{4,}$", vuln):
                    query_builder.add_filter(f"vuln:{vuln}", operator=operator)
                    display_message(stdscr, f"Filter added: vuln:{vuln}", 6)
                else:
                    display_message(stdscr, f"Invalid CVE format: {vuln}", 5)
            elif choice == 3:
                phrase = prompt_input(stdscr, "Enter the key phrase (e.g., admin): ")
                if phrase:
                    if " " in phrase and not (phrase.startswith('"') and phrase.endswith('"')):
                        phrase = f'"{phrase}"'
                    query_builder.add_filter(phrase, operator=operator)
                    display_message(stdscr, f"Filter added: {phrase}", 6)
                else:
                    display_message(stdscr, "Key phrase cannot be empty.", 5)
            elif choice == 4:
                product = prompt_input(stdscr, "Enter the product name (e.g., Apache): ")
                if product:
                    query_builder.add_filter(f"product:{product}", operator=operator)
                    display_message(stdscr, f"Filter added: product:{product}", 6)
                else:
                    display_message(stdscr, "Product name cannot be empty.", 5)
            elif choice == 5:
                country = prompt_input(stdscr, "Enter the country code (e.g., US): ").upper()
                if re.match(r"^[A-Z]{2}$", country):
                    query_builder.add_filter(f"country:{country}", operator=operator)
                    display_message(stdscr, f"Filter added: country:{country}", 6)
                else:
                    display_message(stdscr, f"Invalid country code: {country}", 5)
            elif choice == 6:
                city = prompt_input(stdscr, "Enter the city (e.g., \"New York\"): ")
                if city:
                    if " " in city and not (city.startswith('"') and city.endswith('"')):
                        city = f'"{city}"'
                    query_builder.add_filter(f"city:{city}", operator=operator)
                    display_message(stdscr, f"Filter added: city:{city}", 6)
                else:
                    display_message(stdscr, "City cannot be empty.", 5)
            elif choice == 7:
                os_name = prompt_input(stdscr, "Enter the operating system (e.g., \"Windows 10\"): ")
                if os_name:
                    if " " in os_name and not (os_name.startswith('"') and os_name.endswith('"')):
                        os_name = f'"{os_name}"'
                    query_builder.add_filter(f"os:{os_name}", operator=operator)
                    display_message(stdscr, f"Filter added: os:{os_name}", 6)
                else:
                    display_message(stdscr, "Operating system cannot be empty.", 5)
            elif choice == 8:
                raw_filter = prompt_input(stdscr, "Enter the raw filter string (e.g., title:\"Login Page\"): ")
                if raw_filter:
                    query_builder.add_filter(raw_filter, operator=operator)
                    display_message(stdscr, f"Raw filter added: {raw_filter}", 6)
                else:
                    display_message(stdscr, "Raw filter cannot be empty.", 5)
            elif choice == 9:
                break
        elif key in [ord('q'), ord('Q')]:
            break

def finalize_and_execute_query(stdscr):
    """
    Finalizes the query, allows manual editing, and executes the Shodan search.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    query = query_builder.get_query()

    stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
    stdscr.addstr(2, 2, "Finalize and Execute Query")
    stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)

    stdscr.addstr(4, 2, f"Current Query: {query}")
    stdscr.addstr(6, 2, "1. Edit Query Manually")
    stdscr.addstr(7, 2, "2. Execute Query")
    stdscr.addstr(8, 2, "3. Cancel")
    stdscr.refresh()

    key = stdscr.getch()

    if key == ord('1'):
        # Edit Query Manually
        edited_query = prompt_input(stdscr, "Enter the query (leave blank to cancel): ")
        if edited_query:
            query_builder.set_base_query(edited_query)
            display_message(stdscr, f"Query updated to: {edited_query}", 6)
        else:
            display_message(stdscr, "Query editing canceled.", 5)
    elif key == ord('2'):
        # Execute Query
        execute_shodan_query(stdscr)
    elif key == ord('3'):
        # Cancel
        return
    else:
        display_message(stdscr, "Invalid selection.", 5)

def execute_shodan_query(stdscr):
    """
    Executes the Shodan query and handles pagination.
    """
    query = query_builder.get_query()
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, f"Executing Shodan Query: {query}")
    stdscr.refresh()

    page = 1
    global results_cache
    results_cache = []  # Clear previous results

    while True:
        try:
            results = api.search(query, page=page)
            total = results.get('total', 0)
            matches = results.get('matches', [])
            if page == 1:
                display_message(stdscr, f"Total results found: {total}", 6)

            if not matches and page == 1:
                display_message(stdscr, "No results found.", 5)
                return
            elif not matches:
                display_message(stdscr, "No more results.", 5)
                return

            # Display results
            stdscr.clear()
            stdscr.addstr(2, 2, f"Executing Shodan Query: {query}")
            stdscr.addstr(4, 2, f"Displaying Page {page}")
            stdscr.addstr(6, 2, f"{'IP':<15} {'Port':<6} {'Organization':<30}")
            stdscr.addstr(7, 2, "-"*60)

            for idx, match in enumerate(matches, start=8):
                if idx >= height - 5:
                    break  # Prevent writing beyond the screen
                ip = match.get('ip_str', 'N/A')
                port = match.get('port', 'N/A')
                org = match.get('org', 'N/A')
                stdscr.addstr(idx, 2, f"{ip:<15} {port:<6} {org:<30}")
                stdscr.refresh()

            # Store results
            results_cache.extend(matches)

            # Pagination
            stdscr.addstr(height-4, 2, "[P]revious Page  |  [N]ext Page  |  [M]ain Menu")
            stdscr.addstr(height-3, 2, "Choose an action (P/N/M): ")
            stdscr.refresh()
            nav = stdscr.getch()

            if nav in [ord('p'), ord('P')]:
                if page > 1:
                    page -= 1
                else:
                    display_message(stdscr, "Already on the first page.", 5)
            elif nav in [ord('n'), ord('N')]:
                if len(matches) > 0:
                    page += 1
                else:
                    display_message(stdscr, "No more pages.", 5)
            elif nav in [ord('m'), ord('M')]:
                break
            else:
                display_message(stdscr, "Invalid choice.", 5)

        except shodan.APIError as e:
            display_message(stdscr, f"Shodan API Error: {e}", 5)
            logging.error(f"Shodan API Error: {e}")
            break
        except Exception as e:
            display_message(stdscr, f"Unexpected Error: {e}", 5)
            logging.error(f"Unexpected Error: {e}")
            break

def save_results_to_file(stdscr):
    """
    Saves the last query results to a JSON file.
    """
    if not results_cache:
        display_message(stdscr, "No results to save. Execute a query first.", 5)
        return

    filename = prompt_input(stdscr, "Enter filename to save results (e.g., results.json): ")
    if not filename:
        filename = "results.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_cache, f, ensure_ascii=False, indent=4)
        display_message(stdscr, f"Results saved to {filename}", 6)
    except Exception as e:
        display_message(stdscr, f"Error saving file: {e}", 5)
        logging.error(f"File Save Error: {e}")

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def manage_alerts_menu(stdscr):
    """
    Provides options to create, list, and delete Shodan alerts.
    """
    menu_options = [
        "1. Create a new alert",
        "2. List existing alerts",
        "3. Delete an alert",
        "4. Return to main menu"
    ]

    selected_idx = 0
    while True:
        draw_sub_menu(stdscr, "Shodan Alerts Management", menu_options, selected_idx)
        key = stdscr.getch()

        if key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
            selected_idx += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            choice = selected_idx + 1
            if choice == 1:
                create_alert(stdscr)
            elif choice == 2:
                list_alerts(stdscr)
            elif choice == 3:
                delete_alert(stdscr)
            elif choice == 4:
                break
        elif key in [ord('q'), ord('Q')]:
            break
        else:
            pass  # Ignore other keys

def create_alert(stdscr):
    """
    Creates a new Shodan alert.
    """
    name = prompt_input(stdscr, "Enter a name for the alert: ")
    ip_range = prompt_input(stdscr, "Enter the network or IP to monitor (e.g., 1.2.3.0/24): ")

    if not name or not ip_range:
        display_message(stdscr, "Name and IP range are required.", 5)
        return

    try:
        alert = api.create_alert(name, ip_range)
        display_message(stdscr, f"Alert created: ID {alert['id']}", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def list_alerts(stdscr):
    """
    Lists existing Shodan alerts.
    """
    try:
        alerts = api.alerts()
        if not alerts:
            display_message(stdscr, "No alerts found.", 5)
            return

        menu_options = [f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}" for a in alerts]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Existing Shodan Alerts", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def delete_alert(stdscr):
    """
    Deletes a Shodan alert based on alert ID.
    """
    alert_id = prompt_input(stdscr, "Enter the alert ID to delete: ")
    if not alert_id:
        display_message(stdscr, "Alert ID cannot be empty.", 5)
        return

    try:
        api.delete_alert(alert_id)
        display_message(stdscr, f"Alert {alert_id} deleted successfully.", 6)
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def start_new_query(stdscr):
    """
    Starts a new clean query by resetting the query builder and results cache.
    """
    query_builder.reset()
    global results_cache
    results_cache = []
    display_message(stdscr, "A new, clean query has been started. Previous query and results cleared.", 6)

def add_trending_cve_filter(stdscr):
    """
    Allows the user to add trending CVE-based queries as filters.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.addstr(2, 2, "Fetching trending CVE-based queries from Shodan...")
    stdscr.refresh()

    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            display_message(stdscr, "No trending CVE-based queries found at this time.", 5)
            return

        # Display top 10 trending CVE queries
        menu_options = [f"Title: {q['title']} | Query: {q['query']}" for q in cve_queries[:10]]
        selected_idx = 0

        while True:
            draw_sub_menu(stdscr, "Trending CVE Queries", menu_options, selected_idx)
            key = stdscr.getch()

            if key == curses.KEY_UP and selected_idx > 0:
                selected_idx -= 1
            elif key == curses.KEY_DOWN and selected_idx < len(menu_options) - 1:
                selected_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_query = cve_queries[selected_idx]['query']
                operator = prompt_input(stdscr, "Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").upper()
                if operator not in ["AND", "OR"]:
                    operator = "AND"
                query_builder.add_filter(chosen_query, operator=operator)
                display_message(stdscr, f"CVE Filter added: {chosen_query}", 6)
                break
            elif key in [ord('q'), ord('Q')]:
                break
            else:
                pass  # Ignore other keys

    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def view_stats(stdscr):
    """
    Displays stats/facets for the current query.
    """
    query = query_builder.get_query()
    if query == "*":
        display_message(stdscr, "No active query to view stats for.", 5)
        return

    prompt = "Enter a comma-separated list of facets to view (e.g., port, country, org): "
    facets_input = prompt_input(stdscr, prompt)
    facets = [f.strip() for f in facets_input.split(',') if f.strip()]

    if not facets:
        display_message(stdscr, "No valid facets entered.", 5)
        return

    try:
        facet_str = ",".join([f"{f}:10" for f in facets])  # Top 10 results per facet
        results = api.count(query, facets=facet_str)

        if 'facets' not in results:
            display_message(stdscr, "No facet information returned.", 5)
            return

        display_text = f"Stats for Query: {query}\n{'='*50}\n"
        for facet in facets:
            if facet in results['facets']:
                display_text += f"Top {facet.capitalize()}s:\n"
                for item in results['facets'][facet]:
                    val, count = item['value'], item['count']
                    display_text += f"  {val}: {count}\n"
                display_text += '-'*50 + '\n'
            else:
                display_text += f"No data for facet '{facet}'.\n{'-'*50}\n"

        display_output(stdscr, display_text, "cyan")
    except shodan.APIError as e:
        display_message(stdscr, f"Shodan API Error: {e}", 5)
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        display_message(stdscr, f"Unexpected Error: {e}", 5)
        logging.error(f"Unexpected Error: {e}")

def draw_sub_menu(stdscr, title, menu_options, selected_idx):
    """
    Draws a sub-menu with the given title and options.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Draw a border
    stdscr.border(0)

    # Add header
    header = f"===== {title} ====="
    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
    stdscr.addstr(1, width//2 - len(header)//2, header)
    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

    # Add menu items
    for idx, option in enumerate(menu_options):
        x = 4
        y = 3 + idx
        if idx == selected_idx:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, f"> {option}")
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, f"  {option}")
            stdscr.attroff(curses.color_pair(2))

    # Add footer
    footer = "Use Arrow Keys to Navigate and Enter to Select"
    stdscr.attron(curses.color_pair(4))
    stdscr.addstr(height-2, width//2 - len(footer)//2, footer)
    stdscr.attroff(curses.color_pair(4))

    stdscr.refresh()

def display_output(stdscr, output, color_name):
    """
    Displays the output text with scrolling capability.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    lines = output.split('\n')
    max_lines = height - 6
    current_line = 0

    # Map color names to color pairs
    color_map = {
        "red": 5,
        "yellow": 6,
        "green": 6,
        "cyan": 4  # Using footer color for display
    }
    color_pair = color_map.get(color_name.lower(), 2)

    while True:
        stdscr.clear()
        stdscr.attron(curses.color_pair(color_pair))
        for idx in range(max_lines):
            if current_line + idx < len(lines):
                try:
                    stdscr.addstr(2 + idx, 2, lines[current_line + idx])
                except curses.error:
                    pass  # Ignore if writing outside the window
        stdscr.attroff(curses.color_pair(color_pair))

        # Footer
        footer = "Use Arrow Keys to Scroll, 'q' to Quit"
        stdscr.attron(curses.color_pair(4))
        stdscr.addstr(height-2, width//2 - len(footer)//2, footer)
        stdscr.attroff(curses.color_pair(4))
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_DOWN and current_line + max_lines < len(lines):
            current_line += 1
        elif key == curses.KEY_UP and current_line > 0:
            current_line -= 1
        elif key in [ord('q'), ord('Q')]:
            break

def display_message(stdscr, message, color_pair):
    """
    Displays a centered message with a specified color pair.
    """
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    stdscr.attron(curses.color_pair(color_pair))
    stdscr.addstr(height//2 - 1, width//2 - len(message)//2, message)
    stdscr.attroff(curses.color_pair(color_pair))
    stdscr.addstr(height//2 + 1, width//2 - len("Press any key to continue...")//2, "Press any key to continue...")
    stdscr.refresh()
    stdscr.getch()

def exit_program(stdscr):
    """
    Exits the program gracefully.
    """
    curses.endwin()
    sys.exit()

# -------------------- Main Execution -------------------- #

if __name__ == "__main__":
    curses.wrapper(main_menu)
