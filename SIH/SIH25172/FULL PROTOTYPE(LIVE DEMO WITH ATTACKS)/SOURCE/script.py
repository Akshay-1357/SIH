# Create complete project structure
import os
import json

# Create all directories
directories = [
    "webapp-ml-waf",
    "webapp-ml-waf/scripts",
    "webapp-ml-waf/src", 
    "webapp-ml-waf/data",
    "webapp-ml-waf/model",
    "webapp-ml-waf/model/final",
    "webapp-ml-waf/demo",
    "webapp-ml-waf/config",
    "webapp-ml-waf/logs",
    "webapp-ml-waf/tests",
    "webapp-ml-waf/docker"
]

for dir_path in directories:
    os.makedirs(dir_path, exist_ok=True)

print("✅ Created complete project structure")

# Show the structure
def show_tree(path, prefix="", max_depth=3, current_depth=0):
    if current_depth >= max_depth:
        return
    items = sorted([x for x in os.listdir(path) if not x.startswith('.')])
    for i, item in enumerate(items):
        item_path = os.path.join(path, item)
        is_last = i == len(items) - 1
        current_prefix = "└── " if is_last else "├── "
        print(f"{prefix}{current_prefix}{item}")
        
        if os.path.isdir(item_path):
            extension = "    " if is_last else "│   "
            show_tree(item_path, prefix + extension, max_depth, current_depth + 1)

print("\nProject Structure:")
show_tree("webapp-ml-waf")