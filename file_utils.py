import os
def select_file(file_name):
    if os.path.isfile(file_name):
        print(f"Select file: {file_name}")
    else:
        print(f"File {file_name} does not exist.")
def file_handling(filename):
    ip_address = None
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if "Received-SPF:" in line:
                prefix = "client-ip="
                start = line.find(prefix) + len(prefix)
                end = line.find(";", start)
                if start != -1 and end != -1:
                    ip_address = line[start:end]
                    break  # Stop searching after finding the first IP address

    if ip_address:
        return ip_address
    else:
        print("No IP address found.")
        return 0
