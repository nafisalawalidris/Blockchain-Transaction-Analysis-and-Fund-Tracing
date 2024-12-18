import os
import logging
from datetime import datetime
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import whois
from web3 import Web3
import json
from fpdf import FPDF
import matplotlib.pyplot as plt
import networkx as nx
from dotenv import load_dotenv
import requests

# Load environment variables (API key)
load_dotenv()

# API URLs and keys
TRON_API_URL = "https://apilist.tronscan.org/api/transaction"
tron_api_key = os.getenv("TRONSCAN_API_KEY")

# Set up logging for better monitoring and error tracking
logging.basicConfig(
    filename="blockchain_analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Convert timestamp from milliseconds to human-readable format
def convert_timestamp(timestamp):
    """Converts timestamp from milliseconds to human-readable format."""
    return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')

# Validate API key
def validate_api_keys():
    """Validates the presence of the Tron API key."""
    if tron_api_key:
        logging.info("Tron API key loaded successfully.")
        print("Tron API key loaded successfully.")
    else:
        logging.warning("Tron API key is missing. Ensure your .env file is set up correctly.")
        print("Warning: Tron API key is missing.")

# Main execution (for testing library imports)
def check_libraries():
    try:
        # Test if the necessary libraries are imported
        import requests
        print("requests library installed successfully.")

        import whois
        print("whois library installed successfully.")

        from bs4 import BeautifulSoup
        print("beautifulsoup4 library installed successfully.")

        from datetime import datetime
        print("datetime library installed successfully.")

        # If no errors, all libraries are installed
        print("\nAll libraries installed successfully!")

    except ImportError as e:
        print(f"Error: {e.name} library is not installed.")

if __name__ == "__main__":
    # Check if libraries are installed and ready to use
    check_libraries()

    # Validate API keys
    validate_api_keys()

# Define the transaction details
initial_transfer = {
    "transaction_date": datetime(2024, 11, 27, 12, 30),  # Date and time of the transfer
    "status": "Withdrawal Successful",
    "cryptocurrency": "USDT (Tether)",
    "network": "TRON (TRC-20)",
    "amount": 20.0,
    "transaction_fee": 5.0,
    "fee_received": 15.0,
    "discrepancy_note": "The discrepancy in fee received is due to network transaction costs or miner's fees",
    "withdrawal_address": "TWHvZDcEsALvs6gmvnazAhuyn89icDQHtp",
    "recipient_address": "TPZMBfD312Ss9jjwLyVtRkXap33nYZyqpT"
}

subsequent_transfer = {
    "request_date": datetime(2024, 11, 27, 12, 40),  # Date and time of the transfer request
    "amount_requested": 9172.883118,
    "transaction_fee": 5.0,
    "net_amount_transferred": 9172.703118,
    "cryptocurrency": "USDT (Tether)",
    "network": "TRON (TRC-20)",
    "recipient_address": "TPZMBfD312Ss9jjwLyVtRkXap33nYZyqpT",
    "coinunited_status": "Withdrawal Successful (marked at 12:42 PM UTC)",
    "platform_status": "Processing (as of 1:17 PM UTC on the same day)"
}

# Function to log and display the transactions
def display_transaction_details(transfer_type, transaction_details):
    print(f"{transfer_type} Transaction Details:")
    for key, value in transaction_details.items():
        print(f"- {key.replace('_', ' ').capitalize()}: {value}")
    print()

# Displaying both transactions
display_transaction_details("Initial", initial_transfer)
display_transaction_details("Subsequent", subsequent_transfer)

# Function to fetch historical transactions for a given Tron address
def fetch_tron_transactions(address, limit=10, page=1):
    try:
        url = f"{TRON_API_URL}?address={address}&limit={limit}&start={limit * (page - 1)}&orderBy=timestamp&sort=desc"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if "data" in data:
            return data["data"]
        else:
            logging.warning("No data found or error in response.")
            return None
    except RequestException as e:
        logging.error(f"Error fetching transactions: {e}")
        return None

# Function to display and log transactions related to the specified address
def display_tron_transactions(address):
    limit = 10  # Set the limit for the number of transactions per page
    page = 1  # Start with the first page
    all_transactions = []

    while True:
        logging.info(f"Fetching transactions for address: {address}, page {page}")
        transactions = fetch_tron_transactions(address, limit=limit, page=page)
        
        if transactions:
            for txn in transactions:
                timestamp = txn.get('timestamp', 0)
                converted_timestamp = convert_timestamp(timestamp)
                txn_id = txn.get('hash', 'N/A')
                amount = txn.get('amount', 'N/A')
                sender = txn.get('fromAddress', 'N/A')
                recipient = txn.get('toAddress', 'N/A')

                logging.info(f"Transaction ID: {txn_id}")
                logging.info(f"Sender: {sender}")
                logging.info(f"Recipient: {recipient}")
                logging.info(f"Amount: {amount}")
                logging.info(f"Timestamp: {converted_timestamp}")
                logging.info("-" * 50)

                # Store all transactions for further analysis or tracking
                all_transactions.append(txn)

            if len(transactions) < limit:
                logging.info("No more transactions to fetch.")
                break
            else:
                page += 1
        else:
            logging.info("No transactions found or unable to fetch data.")
            break
    
    return all_transactions

# Function to search for a specific transaction by its hash
def search_transaction_by_hash(all_transactions, txn_hash):
    for txn in all_transactions:
        if txn.get('hash') == txn_hash:
            return txn
    return None

# Filter transactions by specific amounts
def filter_transactions(transactions, amount):
    return [tx for tx in transactions if tx.get('amount') == amount]

# Handle missing hash transactions for specific amounts
def check_transactions_without_hash(transactions, amount):
    for txn in transactions:
        if txn.get('amount') == amount and txn.get('hash') is None:
            logging.warning(f"Transaction with amount {amount} has no TX hash.")
            return txn
    return None

# Trace the chain of transactions
def trace_transaction_chain(transactions, start_address):
    traced_transactions = []
    current_addresses = {start_address}

    while current_addresses:
        next_addresses = set()
        for tx in transactions:
            if tx.get('fromAddress') in current_addresses:
                traced_transactions.append(tx)
                next_addresses.add(tx.get('toAddress'))
        current_addresses = next_addresses

    return traced_transactions

# Create a visual graph of the transaction chain
def create_transaction_graph(transactions, output_file):
    graph = nx.DiGraph()
    for tx in transactions:
        graph.add_edge(tx.get('fromAddress'), tx.get('toAddress'), weight=tx.get('amount', 0))

    pos = nx.spring_layout(graph)
    plt.figure(figsize=(10, 8))
    nx.draw(graph, pos, with_labels=True, node_size=700, font_size=10, node_color='skyblue', edge_color='gray')
    labels = nx.get_edge_attributes(graph, 'weight')
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=labels)
    plt.title("Transaction Flow")
    plt.savefig(output_file)
    plt.close()

# Generate a structured PDF report
def generate_pdf_report(filtered_transactions, traced_transactions, graph_image, report_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", size=16)
    pdf.cell(200, 10, txt="Transaction Trace Report", ln=True, align='C')
    pdf.ln(10)

    # Filtered Transactions Section
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Filtered Transactions (Specific Amounts):", ln=True)
    pdf.ln(5)
    for tx in filtered_transactions:
        pdf.cell(200, 10, txt=f"From: {tx.get('fromAddress')} To: {tx.get('toAddress')} Amount: {tx.get('amount')} Hash: {tx.get('hash')}", ln=True)

    pdf.ln(10)

    # Traced Transactions Section
    pdf.cell(200, 10, txt="Traced Transactions (Fund Movement):", ln=True)
    pdf.ln(5)
    for tx in traced_transactions:
        pdf.cell(200, 10, txt=f"From: {tx.get('fromAddress')} To: {tx.get('toAddress')} Amount: {tx.get('amount')} Hash: {tx.get('hash')}", ln=True)

    pdf.ln(10)

    # Transaction Flow Graph
    pdf.cell(200, 10, txt="Transaction Flow Graph:", ln=True)
    pdf.image(graph_image, x=10, y=pdf.get_y(), w=180)

    # Output PDF
    pdf.output(report_file)
    logging.info(f"PDF report saved as {report_file}")

# Scrape website and perform WHOIS lookup
def scrape_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No title found"
        return title
    except RequestException as e:
        logging.error(f"Error fetching the website: {e}")
        return None

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        logging.error(f"Error performing WHOIS lookup: {e}")
        return None

# Sample usage:
if __name__ == "__main__":
    # Example: Get and trace transactions for an address
    transactions = display_tron_transactions("TXYf76s7Hp9KhDg9Rm3yRcrpZTkA6URQNR")

    # Filter by a specific amount
    filtered = filter_transactions(transactions, 20.0)

    # Trace chain of transactions
    traced_chain = trace_transaction_chain(transactions, "TXYf76s7Hp9KhDg9Rm3yRcrpZTkA6URQNR")

    # Create graph and PDF
    create_transaction_graph(traced_chain, "transaction_graph.png")
    generate_pdf_report(filtered, traced_chain, "transaction_graph.png", "transaction_report.pdf")

    # Scrape a website
    website_title = scrape_website("https://coinunited.io")
    if website_title:
        logging.info(f"Website Title: {website_title}")

    # WHOIS Lookup for suspicious domain
    domain_info = whois_lookup("coinunited.io")
    if domain_info:
        logging.info(f"WHOIS Information: {domain_info}")
