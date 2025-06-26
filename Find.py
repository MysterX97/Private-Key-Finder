import os
import requests
import secrets
import concurrent.futures
import threading
import time
from eth_account import Account
from termcolor import colored

# --- Configuration ---
# API keys for various blockchain explorers
# !!! WARNING: Your API key should be protected and not shared with others.
NETWORK_CONFIGS = {
    "Ethereum": {
        "api_base": "https://api.etherscan.io/api",
        "api_key": "W1VJHMIXZ4564978Z4IBRBSMNTH2DRW5AP", # Your Etherscan API key
        "native_symbol": "ETH",
        "price_usd": 3500 # Current price of Ethereum in USD (update as needed)
    },
    "Polygon": {
        "api_base": "https://api.polygonscan.com/api",
        "api_key": "1YCD8BF4UGDET6D353PPM5IABD8Y3EH76P", # Your Polygonscan API key
        "native_symbol": "MATIC",
        "price_usd": 0.75 # Current price of Polygon in USD (update as needed)
    }
}

BALANCE_THRESHOLD_USD = 0.001
OUTPUT_FILE = "found_wallets.txt"
TOTAL_WALLETS = 98000 # Total number of wallets to check (per network)
MAX_THREADS = 10
TARGET_WALLETS_PER_SECOND = 4.5 # Rate set to 4.5 checks per second (based on API limits)

# Global locks and variables for rate limiting
_rate_limit_lock = threading.Lock()
_last_api_call_time = 0.0
# Minimum delay between API calls (in seconds) to maintain approximate rate
_min_delay_between_calls = 1.0 / TARGET_WALLETS_PER_SECOND

save_lock = threading.Lock() # Lock for synchronizing file writes

# Optional libraries, check if installed (moved from top level to ensure all warnings are in English)
Key = None
try:
    from bitcoinlib.keys import Key
except ImportError:
    print(colored("Warning: 'bitcoinlib' is not installed. Bitcoin functionality will be limited. BTC addresses cannot be generated.", "red"))

SolanaKeypair = None
SolanaPublicKey = None
try:
    from solana.keypair import Keypair as SolanaKeypair
    from solana.publickey import PublicKey as SolanaPublicKey
except ImportError:
    print(colored("Warning: 'solana' library is not installed. Solana functionality will be limited.", "yellow"))
    SolanaKeypair = None
    SolanaPublicKey = None

Tron = None
TronPrivateKey = None
try:
    from tronpy import Tron
    from tronpy.keys import PrivateKey as TronPrivateKey
except ImportError:
    print(colored("Warning: 'tronpy' is not installed. Tron functionality will be limited.", "yellow"))
    Tron = None
    TronPrivateKey = None


def get_evm_balance_api(address: str, network_name: str) -> float:
    """
    Fetches the EVM network (Ethereum, Polygon) balance in USD using the respective API.
    Rate limiting is enabled.
    """
    global _last_api_call_time

    network_config = NETWORK_CONFIGS[network_name]
    api_base = network_config["api_base"]
    api_key = network_config["api_key"]
    native_symbol = network_config["native_symbol"]
    price_usd = network_config["price_usd"]

    # --- Rate Limiting Code (Enabled) ---
    with _rate_limit_lock:
        current_time = time.monotonic()
        elapsed = current_time - _last_api_call_time
        wait_time = _min_delay_between_calls - elapsed
        if wait_time > 0:
            time.sleep(wait_time) # This line pauses calls
        _last_api_call_time = time.monotonic()
    # --- End of Rate Limiting Code ---

    url = f"{api_base}?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status() # Raise for HTTP errors
        result = resp.json()

        if result.get("status") == "1":
            balance_wei = int(result.get("result", "0"))
            balance_native = balance_wei / 1e18
            balance_usd = balance_native * price_usd
            return balance_usd
        elif result.get("status") == "0":
            msg = result.get("message", "Unknown error")
            print(colored(f"[!] {network_name} API error for address {address}: {msg}", "red"))
        else:
            print(colored(f"[!] Unexpected {network_name} API response for address {address}: {result}", "red"))
    except requests.exceptions.Timeout:
        print(colored(f"[!] {network_name} request timed out for address {address}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] {network_name} network error for address {address}: {e}", "red"))
    except Exception as e:
        print(colored(f"[!] Unexpected error for {network_name} address {address}: {e}", "red"))
    return 0.0

def save_result(network_name: str, priv_key: str, address: str, balance_usd: float):
    """
    Saves found wallets to the output file.
    """
    with save_lock: # Ensures synchronized file access from multiple threads
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"Network: {network_name}\n")
            f.write(f"Private Key: {priv_key}\n")
            f.write(f"Address: {address}\n")
            f.write(f"USD Balance: ${balance_usd:.4f}\n")
            f.write("="*50 + "\n")

def process_wallet(index: int):
    """
    Processes a single wallet - generates key, address, and checks balance on all configured networks.
    """
    priv_key_hex = secrets.token_hex(32)
    priv_key_with_prefix = "0x" + priv_key_hex
    
    try:
        acct = Account.from_key(priv_key_hex) # eth_account expects hex string without prefix
        address = acct.address
    except Exception as e:
        print(colored(f"[-] Error generating address from private key (index {index}): {e}", "red"))
        return

    # Check for all configured networks
    for network_name, config in NETWORK_CONFIGS.items():
        balance_usd = get_evm_balance_api(address, network_name) # Call the EVM balance function

        if balance_usd > BALANCE_THRESHOLD_USD:
            print(colored(f"✅ [{index}] Balance found ({network_name}): ${balance_usd:.4f} @ {address}", "green"))
            save_result(network_name, priv_key_with_prefix, address, balance_usd)
        else:
            # This can be very verbose output if checking many empty wallets.
            # You can comment this line out if the console fills up too quickly.
            print(colored(f"❌ [{index}] Balance 0 ({network_name}) - {address}", "red"))

def main():
    # Validate API keys
    for net_name, config in NETWORK_CONFIGS.items():
        if not config["api_key"] or config["api_key"] == f"YOUR_{net_name.upper()}_API_KEY":
            print(colored(f"!!! Please enter your {net_name} API KEY in the {net_name.upper()} configuration within the NETWORK_CONFIGS variable !!!", "red"))
            return

    print(colored("--- Ethereum and Polygon Wallet Balance Scanner ---", "cyan"))
    print(colored(f"Rate Limiting Enabled: Targeting {TARGET_WALLETS_PER_SECOND} API calls/second", "green"))
    print(colored(f"Minimum Balance Threshold (USD): ${BALANCE_THRESHOLD_USD}", "blue"))
    print(colored(f"Output File: {OUTPUT_FILE}", "blue"))
    print(colored(f"Total Wallets to Check (per network): {TOTAL_WALLETS}", "blue"))
    print(colored(f"Maximum Threads: {MAX_THREADS}", "blue"))
    print(colored("-" * 50, "white"))

    # Initialize output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("--- Found Ethereum and Polygon Wallets with Balance ---\n\n")

    # Multi-threaded execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(process_wallet, i) for i in range(1, TOTAL_WALLETS + 1)]
        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result() # Retrieve result (or exception)
            except Exception as e:
                print(colored(f"[!] Error processing wallet: {e}", "red"))

    print(colored("\n--- Scan Finished ---", "cyan"))

if __name__ == "__main__":
    main()
