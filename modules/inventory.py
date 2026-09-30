import os
import pandas as pd
def load_inventory_data():
    """Loads wireless discovery data using an absolute path to prevent file not found errors."""
    # Find the exact directory where inventory.py lives
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the path to the data folder (one level up, then into 'data')
    filepath = os.path.join(current_dir, "..", "data", "sample_kismet.csv")
    
    if not os.path.exists(filepath):
        return pd.DataFrame()
    return pd.read_csv(filepath)