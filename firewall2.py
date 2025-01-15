import ipaddress
import os

rules = []

# Rule addition method which delegates to the appropriate method based on the direction
def add_rule(ruleno, direction, addr):
    if '-' in addr:
        iprange_insert(ruleno, direction, addr)
    else:
        if direction is None:
            # Add for both incoming and outgoing directions with the same rule number when no direction is specified
            bidirectional_insert(ruleno, addr)
        else:
            # Add for the specified direction only
            single_insert(ruleno, direction, addr)

# In case of Ip range input, the ranges are split and added as individual ip address rules
def iprange_insert(ruleno, direction, addr):
   iprange_start, iprange_end = addr.split('-')
   iprange_start = ipaddress.IPv4Address(iprange_start)
   iprange_end = ipaddress.IPv4Address(iprange_end)

    # Iterate through the range and add each IP address, reversed is used to ensure that starting ip gets highest priority
   for ip in reversed(range(int(iprange_start), int(iprange_end) + 1)):
        ip_str = str(ipaddress.IPv4Address(ip))  #Individual Ip address are converted to string to be passed to the insert method
        if direction is None: 
            bidirectional_insert(ruleno, ip_str)
        else:     
            single_insert(ruleno, direction, ip_str)

 # Helper function to find matching rules, can filter based on a combination of rule number, direction, and address
def find_rules(ruleno=None, direction=None, addr=None):
    return [
        rule for rule in rules  #Check for a rule matching in the rules list
        if (ruleno is None or rule['rule'] == ruleno) and
           (direction is None or rule['direction'] == direction) and
           (addr is None or rule['addr'] == addr)
    ]

# Adding rules for both directions 
def bidirectional_insert(ruleno, addr):
    single_insert(ruleno, '-in', addr)
    single_insert(ruleno, '-out', addr)           

# Add a single rule for outgoing or incoming direction
def single_insert(ruleno, direction, addr):
    new_rule = {'rule': ruleno, 'direction': direction, 'addr': addr}

    if find_rules(ruleno, direction, addr):  # Check if exactly same rule exists preventing duplicates
        print(f"Error: Rule {ruleno} with direction {direction} and address {addr} already exists.")
        return

    if find_rules(ruleno, direction):  # Check if rule with same number and direction exists then adjust priorities
        adjustpriorities(ruleno)
     
    rules.append(new_rule)
    rules.sort(key=lambda x: (x['rule'], x['direction']))  # Sort rules based on rule number first and then direction

def adjustpriorities(ruleno):
    for rule in rules:
        if rule['rule'] >= ruleno:
            rule['rule'] += 1  # Rule number is incremented for matching existing rule numbers already in the list

def remove_rule(ruleno, direction=None):
    global rules   # Accessing the global rules list
    rulefound = False  # Flag to check if the rule is found

    # Step 1: Find matching rules based on the input criteria
    if direction is None:
        rules_for_removal = find_rules(ruleno=ruleno)  # Remove all rules with the specified rule number
    else:
        rules_for_removal = find_rules(ruleno=ruleno, direction=direction)  # Remove only the rule with the specified direction

    if rules_for_removal: #once rules for removal are found they must be removd from the main list
        rules = [rule for rule in rules if rule not in rules_for_removal] #Removing the matching rules from the main list
        rulefound = True

    if not rulefound:
        print(f"Error: Rule {ruleno} not found. Please enter a valid command.")


# Listing firewall rules based on the criteria, each filter method redirects to dedicated helper method
def list_rules(ruleno=None, direction=None, addr=None):
    filtered_rules = rules
    if ruleno:
        filtered_rules = filter_byruleno(filtered_rules, ruleno)
    if direction:
        filtered_rules = filter_bydirection(filtered_rules, direction)
    if addr:
       filtered_rules = filter_byaddr(filtered_rules, addr)
    for rule in filtered_rules:
        print(f"Rule {rule['rule']} | Direction: {rule['direction']} | Address: {rule['addr']}")

# List of rules given based on given ruleno
def filter_byruleno(rules_list, ruleno):
    return [rule for rule in rules_list if rule['rule'] == ruleno]

# List of rules given based on given direction
def filter_bydirection(rules_list, direction):
    return [rule for rule in rules_list if rule['direction'] == direction]

# List of rules given based on IP address or address range
def filter_byaddr(rules_list, addr):
    if '-' in addr:
        # If the address is a range, filter based on the range
       iprange_start, iprange_end = addr.split('-')
       iprange_start = ipaddress.IPv4Address(iprange_start)
       iprange_end = ipaddress.IPv4Address(iprange_end)
       filtered_rules = [rule for rule in rules_list if iprange_start <= ipaddress.IPv4Address(rule['addr']) <= iprange_end]
    else:
        # If the address is a single IP, filter based on the exact match
        filtered_rules = [rule for rule in rules_list if rule['addr'] == addr]
    return filtered_rules

# Save rules to a file (called by the save command during runtime)
def savefile(filename):
    try:
        with open(filename, 'w') as file:
            for rule in rules:
                file.write(f"{rule['rule']} {rule['direction']} {rule['addr']}\n")
        print(f"Rules successfully saved to {filename}.")
    except Exception as e:
        print(f"Error: Unable to save firewall rules to file. {e}")

# Load rules from a file (used by the loadfile_runtime method)
def loadfile(filename):
    global rules 
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as file:
                rules.clear()  # For simplicity, we are considering to clear the existing rules before loading new ones
                for line in file:
                    rule_sections = line.strip().split()
                    if len(rule_sections) == 3:
                        ruleno = int(rule_sections[0])
                        direction = rule_sections[1]
                        addr = rule_sections[2]
                        rules.append({'rule': ruleno, 'direction': direction, 'addr': addr})
                rules.sort(key=lambda x: (x['rule'], x['direction']))
            print(f"Rules successfully loaded from {filename}.")
        except Exception as e:
            print(f"Error: Unable to load firewall rules from file. {e}")
    else:
        print(f"Error: File {filename} cannot be found. Please enter the filename again or type 'exit' to cancel.")
        return False
    return True

# Load rules from file during runtime (called by the load command)
def loadfile_runtime():
    while True:
        filename = input("Enter the filename to load rules from: ").strip()
        if filename.lower() == 'cancel':
            return
        if loadfile(filename):
            break

# Input handler for add command, requires at least 2 parameters add command and ipaddress is mandatory    
def add_handler(command):
    if len(command) < 2:
        print("Error: Insufficient parameters for add command.")
        return

    ruleno = 1
    direction = None
    addr = None

    #Extracting parameters from the input command assigning them to ruleno, direction and addr
    for param in command[1:]:
        if param.isdigit():
            ruleno = int(param)
        elif param in ['-in', '-out']:
            direction = param
        elif validate_ip(param):
            addr = param

    if not addr:
        print("Error: Invalid or missing IP address.")
        return

    add_rule(ruleno, direction, addr)

# Input handler for remove command, requires at least 2 parameters, rule number is mandatory
def remove_handler(command):
    if len(command) < 2:
        print("Error: Rule number is required for remove command.")
        return

    #Only rule number and direction parameters are needed for removing rules
    ruleno = int(command[1])
    direction = command[2] if len(command) > 2 and command[2] in ['-in', '-out'] else None
    remove_rule(ruleno, direction)

# Input handler for list command, does not require any parameters but can work with specific parameters as well
def list_handler(command):
    ruleno = None
    direction = None
    addr = None

    for param in command[1:]:
        if param.isdigit():
            ruleno = int(param)
        elif param in ['-in', '-out']:
            direction = param
        elif validate_ip(param):
            addr = param

    list_rules(ruleno, direction, addr)

# Method to validate IP address or IP range using the IPaddress module in python to check if the input is valid Ipv4 address
def validate_ip(addr):
    try:
        if '-' in addr:
           iprange_start, iprange_end = addr.split('-')
           ipaddress.IPv4Address(iprange_start)
           ipaddress.IPv4Address(iprange_end)
        else:
            ipaddress.IPv4Address(addr)
        return True
    except ValueError:
        return False

def main():
    print("Available commands:\n"
          "  add [ruleno] [-in|-out] IP_address - Add a rule\n"
          "  remove ruleno [-in|-out] - Remove a rule\n"
          "  list [ruleno] [-in|-out] [IP_address|-IP_range] - List rules\n"
          "  load - Load rules from a file\n"
          "  save - Save rules to a file\n"
          "  exit - Exit the program")
    while True:
        command = input("Enter command: ").strip().split()
        if not command:
            continue

        action = command[0]  # Extract the action from the command as it is the first word of the input
        # Actions are handled by the respective handler methods
        if action == 'add':
            add_handler(command)

        elif action == 'remove':
            remove_handler(command)

        elif action == 'list': 
            list_handler(command)

        elif action == 'load':
            loadfile_runtime()
            
        elif action == 'save':
            filename = input("Enter the filename to save rules to: ").strip()
            savefile(filename)

        elif action == 'exit':
            break

        else:
            print("Error: Unknown command.")

if __name__ == "__main__":
    main()
