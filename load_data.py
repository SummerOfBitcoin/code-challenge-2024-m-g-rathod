import os
import json

directory = 'mempool'

# List to store JSON data from all files
json_data_list = []

# Iterate over each JSON file
for filename in os.listdir(directory):
        if filename.endswith(".json"):
            with open(os.path.join(directory, filename), 'r') as file:
                content = json.load(file)
                json_data_list.append((filename, content))