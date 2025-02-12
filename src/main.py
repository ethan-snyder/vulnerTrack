# Imports
import os
from dotenv import load_dotenv
import nvdlib as nvd

# Load environment variables from .env file
load_dotenv()

# Establishing API Key
api_key = os.getenv('API_KEY')

if not api_key:
    raise ValueError("API key not found. Make sure it's stored in the .env file or set as an environment variable.")


user_search = input("Enter a keyword to search for: ")

# Searching CPE
try:
    nvd_query = nvd.searchCPE(keywordSearch=user_search, key=api_key, limit=5)
    print("Search Results for CPE:")
    for result in nvd_query:
        print(result)
except Exception as e:
    print(f"Error during CPE search: {e}")
