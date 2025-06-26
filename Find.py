import os
import requests
import secrets
import concurrent.futures
import threading
import time
from eth_account import Account
from termcolor import colored

# --- კონფიგურაცია ---
# API გასაღებები სხვადასხვა ბლოკჩეინის ექსპლორერებისთვის
# !!! გაფრთხილება: თქვენი API გასაღები უნდა იყოს დაცული და არ უნდა გაუზიაროთ სხვებს.
NETWORK_CONFIGS = {
    "Ethereum": {
        "api_base": "https://api.etherscan.io/api",
        "api_key": "W1VJHMIXZ4564978Z4IBRBSMNTH2DRW5AP", # თქვენი Etherscan API გასაღები
        "native_symbol": "ETH",
        "price_usd": 3500 # Ethereum-ის მიმდინარე ფასი USD-ში (განაახლეთ საჭიროებისამებრ)
    },
    "Polygon": {
        "api_base": "https://api.polygonscan.com/api",
        "api_key": "1YCD8BF4UGDET6D353PPM5IABD8Y3EH76P", # თქვენი Polygonscan API გასაღები
        "native_symbol": "MATIC",
        "price_usd": 0.75 # Polygon-ის მიმდინარე ფასი USD-ში (განაახლეთ საჭიროებისამებრ)
    }
}

BALANCE_THRESHOLD_USD = 0.001
OUTPUT_FILE = "found_wallets.txt"
TOTAL_WALLETS = 98000 # სულ შესამოწმებელი საფულეების რაოდენობა (თითოეულ ქსელზე ცალკე)
MAX_THREADS = 10
TARGET_WALLETS_PER_SECOND = 4.5 # სიჩქარე დაყენებულია წამში 4.5 შემოწმებაზე (API-ის ლიმიტების მიხედვით)

# გლობალური ლოქები და ცვლადები სიჩქარის ლიმიტირებისთვის
_rate_limit_lock = threading.Lock()
_last_api_call_time = 0.0
# მინიმალური დაყოვნება API გამოძახებებს შორის (წამებში), რათა მიახლოებითი სიჩქარე შენარჩუნდეს
_min_delay_between_calls = 1.0 / TARGET_WALLETS_PER_SECOND

save_lock = threading.Lock() # ლოქი ფაილში ჩაწერის სინქრონიზაციისთვის

def get_evm_balance_api(address: str, network_name: str) -> float:
    """
    იღებს EVM ქსელის (Ethereum, Polygon) ბალანსს USD-ში შესაბამისი API-ის გამოყენებით.
    სიჩქარის ლიმიტირება გააქტიურებულია.
    """
    global _last_api_call_time

    network_config = NETWORK_CONFIGS[network_name]
    api_base = network_config["api_base"]
    api_key = network_config["api_key"]
    native_symbol = network_config["native_symbol"]
    price_usd = network_config["price_usd"]

    # --- სიჩქარის ლიმიტირების კოდი (გააქტიურებულია) ---
    with _rate_limit_lock:
        current_time = time.monotonic()
        elapsed = current_time - _last_api_call_time
        wait_time = _min_delay_between_calls - elapsed
        if wait_time > 0:
            time.sleep(wait_time) # ეს ხაზი აყოვნებს გამოძახებებს
        _last_api_call_time = time.monotonic()
    # --- სიჩქარის ლიმიტირების კოდის დასასრული ---

    url = f"{api_base}?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status() # HTTP შეცდომების შემთხვევაში
        result = resp.json()

        if result.get("status") == "1":
            balance_wei = int(result.get("result", "0"))
            balance_native = balance_wei / 1e18
            balance_usd = balance_native * price_usd
            return balance_usd
        elif result.get("status") == "0":
            msg = result.get("message", "უცნობი შეცდომა")
            print(colored(f"[!] {network_name} API შეცდომა მისამართისთვის {address}: {msg}", "red"))
        else:
            print(colored(f"[!] მოულოდნელი {network_name} API პასუხი მისამართისთვის {address}: {result}", "red"))
    except requests.exceptions.Timeout:
        print(colored(f"[!] {network_name} მოთხოვნა timeout-ზე გავიდა მისამართისთვის {address}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] {network_name} ქსელური შეცდომა მისამართისთვის {address}: {e}", "red"))
    except Exception as e:
        print(colored(f"[!] მოულოდნელი შეცდომა {network_name} მისამართისთვის {address}: {e}", "red"))
    return 0.0

def save_result(network_name: str, priv_key: str, address: str, balance_usd: float):
    """
    ინახავს ნაპოვნ საფულეებს გამომავალ ფაილში.
    """
    with save_lock: # უზრუნველყოფს ფაილზე წვდომის სინქრონიზაციას მრავალი თრედიდან
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"Network: {network_name}\n")
            f.write(f"Private Key: {priv_key}\n")
            f.write(f"Address: {address}\n")
            f.write(f"USD Balance: ${balance_usd:.4f}\n")
            f.write("="*50 + "\n")

def process_wallet(index: int):
    """
    ამუშავებს ერთ საფულეს - აგენერირებს გასაღებს, მისამართს და ამოწმებს ბალანსს ყველა კონფიგურირებულ ქსელზე.
    """
    priv_key_hex = secrets.token_hex(32)
    priv_key_with_prefix = "0x" + priv_key_hex
    
    try:
        acct = Account.from_key(priv_key_hex) # eth_account ელოდება ჰექს სტრიქონს პრეფიქსის გარეშე
        address = acct.address
    except Exception as e:
        print(colored(f"[-] შეცდომა მისამართის გენერირებისას პირადი გასაღებიდან (ინდექსი {index}): {e}", "red"))
        return

    # შეამოწმეთ ყველა კონფიგურირებული ქსელისთვის
    for network_name, config in NETWORK_CONFIGS.items():
        balance_usd = get_evm_balance_api(address, network_name) # გამოიძახეთ EVM ბალანსის ფუნქცია

        if balance_usd > BALANCE_THRESHOLD_USD:
            print(colored(f"✅ [{index}] ბალანსი ნაპოვნია ({network_name}): ${balance_usd:.4f} @ {address}", "green"))
            save_result(network_name, priv_key_with_prefix, address, balance_usd)
        else:
            # ეს შეიძლება იყოს ძალიან ბევრი გამომავალი, თუ ცარიელ საფულეებს ამოწმებთ.
            # შეგიძლიათ ეს ხაზი დააკომენტაროთ, თუ კონსოლი ძალიან სწრაფად ივსება.
            print(colored(f"❌ [{index}] ბალანსი 0 ({network_name}) - {address}", "red"))

def main():
    # API გასაღებების ვალიდაცია
    for net_name, config in NETWORK_CONFIGS.items():
        if not config["api_key"] or config["api_key"] == f"YOUR_{net_name.upper()}_API_KEY":
            print(colored(f"!!! გთხოვთ ჩაწეროთ თქვენი {net_name} API KEY {net_name.upper()} კონფიგურაციაში NETWORK_CONFIGS ცვლადში !!!", "red"))
            return

    print(colored("--- Ethereum და Polygon საფულის ბალანსის სკანერი ---", "cyan"))
    print(colored(f"სიჩქარის ლიმიტირება გააქტიურებულია: სამიზნე {TARGET_WALLETS_PER_SECOND} API გამოძახება/წამში", "green"))
    print(colored(f"ბალანსის მინიმალური ზღვარი (USD): ${BALANCE_THRESHOLD_USD}", "blue"))
    print(colored(f"გამომავალი ფაილი: {OUTPUT_FILE}", "blue"))
    print(colored(f"სულ შესამოწმებელი საფულე (თითოეული ქსელისთვის): {TOTAL_WALLETS}", "blue"))
    print(colored(f"მაქსიმალური თრედები: {MAX_THREADS}", "blue"))
    print(colored("-" * 50, "white"))

    # გამომავალი ფაილის ინიციალიზაცია
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("--- ნაპოვნი Ethereum და Polygon საფულეები ბალანსით ---\n\n")

    # მრავალთრედული შესრულება
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(process_wallet, i) for i in range(1, TOTAL_WALLETS + 1)]
        # დაელოდეთ ყველა ტასკის დასრულებას
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result() # ამოიღეთ შედეგი (ან შეცდომა)
            except Exception as e:
                print(colored(f"[!] შეცდომა საფულის დამუშავებისას: {e}", "red"))

    print(colored("\n--- სკანირება დასრულებულია ---", "cyan"))

if __name__ == "__main__":
    main()
