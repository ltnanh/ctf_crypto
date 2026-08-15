#!/usr/bin/env python3
import socket
import json
import sys
import os
import random
from secret import FLAG

def healthcheck(host=None, port=None):
    if host is None:
        host = os.environ.get("HEALTHCHECK_HOST", "localhost")
    if port is None:
        port = int(os.environ.get("HEALTHCHECK_PORT", "5555"))
    """Health check: login and verify products exist"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Receive welcome message
        sock.recv(8192)

        # Receive prompt
        try:
            sock.settimeout(0.5)
            sock.recv(2048)
        except socket.timeout:
            pass

        # Login request
        sock.settimeout(5)
        login_req = {"method": "LOGIN", "params": {"username": "admin", "password": FLAG}}
        sock.send(json.dumps(login_req).encode())

        # Receive login response
        response_data = sock.recv(65536).decode()
        if '>' in response_data:
            response_data = response_data[:response_data.index('>')]

        login_response = json.loads(response_data.strip())
        if login_response.get("status") != "ok":
            print("[-] Healthcheck failed: Login error")
            sock.close()
            return 1

        session = login_response["data"]["session"]

        # Receive prompt before next request
        try:
            sock.settimeout(0.5)
            sock.recv(2048)
        except socket.timeout:
            pass

        # List products request
        sock.settimeout(5)
        products_req = {"method": "LIST_PRODUCTS", "params": {"session": session}}
        sock.send(json.dumps(products_req).encode())

        # Receive products response
        response_data = sock.recv(65536).decode()
        if '>' in response_data:
            response_data = response_data[:response_data.index('>')]

        products_response = json.loads(response_data.strip())

        if products_response.get("status") != "ok" or "products" not in products_response.get("data", {}):
            print("[-] Healthcheck failed: No products found")
            sock.close()
            return 1

        products = products_response["data"]["products"]
        if len(products) == 0:
            print("[-] Healthcheck failed: No products found")
            sock.close()
            return 1

        # Receive prompt before next request
        try:
            sock.settimeout(0.5)
            sock.recv(2048)
        except socket.timeout:
            pass
        sock.settimeout(5)
        # Get a random product
        random_product = random.choice(products)
        get_product_req = {"method": "GET_PRODUCT", "params": {"product_name": random_product["name"], "session": session}}
        sock.send(json.dumps(get_product_req).encode())

        # Receive product response
        response_data = sock.recv(65536).decode()
        if '>' in response_data:
            response_data = response_data[:response_data.index('>')]

        product_response = json.loads(response_data.strip())
        if product_response.get("status") != "ok":
            print("[-] Healthcheck failed: Could not retrieve product")
            sock.close()
            return 1

        # Receive prompt before next request
        try:
            sock.settimeout(0.5)
            sock.recv(2048)
        except socket.timeout:
            pass

        # Get flag request
        sock.settimeout(5)
        flag_req = {"method": "GET_FLAG", "params": {"session": session}}
        sock.send(json.dumps(flag_req).encode())

        # Receive flag response
        response_data = sock.recv(65536).decode()
        if '>' in response_data:
            response_data = response_data[:response_data.index('>')]

        flag_response = json.loads(response_data.strip())
        sock.close()

        if flag_response.get("status") == "ok":
            print(f"[+] Healthcheck passed: {len(products)} products found, flag retrieved")
            return 0

        print("[-] Healthcheck failed: Could not retrieve flag")
        return 1

    except Exception as e:
        print(f"[-] Healthcheck failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(healthcheck())
