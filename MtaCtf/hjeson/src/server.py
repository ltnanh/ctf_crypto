#!/usr/bin/env python3
import base64
from hashlib import md5
import socket
import threading
import json
import sys
import traceback
import time
import uuid
from crypto import CryptoSession
from dispatcher import Dispatcher
from secret import FLAG
from storage import ProductStorage
from session import SessionManager
from cache import RequestCache
from models import Request, Response
from secret import FLAG
from Cryptodome.Random import get_random_bytes

HELP_SHOW_CLIENT = """
Welcome to the Encrypted Product Management Service!
Available commands:
1. LOGIN username password
2. GET_PRODUCT product_name session
3. LIST_PRODUCTS session
4. GET_FLAG session
"""
class EncryptedProductServer:
    def __init__(self, host="127.0.0.1", port=6555, debug=False, cache_size=20):
        self.host = host
        self.port = port
        self.debug = debug

        # Initialize components
        self.products = ProductStorage()
        self.sessions = SessionManager()
        self.dispatcher = Dispatcher(self.products, self.sessions)
        self.request_cache = RequestCache(max_size=cache_size)
        self.cryprosession = CryptoSession()
        # Setup
        self._setup()

    def _setup(self):
        """Initialize admin account and flag product"""
        admin_aes = md5(FLAG.encode()).digest().hex()  
        aes_session_key = md5(b"user_password").digest().hex()  
        
        self.products.create_product("admin", "FLAG", self.cryprosession.encrypt(FLAG, admin_aes))
        self.products.create_product("admin", "Admin Product", self.cryprosession.encrypt("This is an admin-only product", admin_aes))
        self.products.create_product("user01", "Computer", self.cryprosession.encrypt("High-end gaming computer local first", aes_session_key))
        self.products.create_product("user01", "Laptop", self.cryprosession.encrypt("Lightweight business laptop", aes_session_key))
        self.products.create_product("user02", "MTA", self.cryprosession.encrypt("Military Technical Academy", aes_session_key))
        self.products.create_product("user02",  "Tablet", self.cryprosession.encrypt("Latest tablet model", aes_session_key))
        self.products.create_product("user03", "Phone", self.cryprosession.encrypt("Latest smartphone model", aes_session_key))
        self.products.create_product("user03",  "Smartwatch", self.cryprosession.encrypt("Feature-rich smartwatch", aes_session_key))    

    def start(self):
        """Start TCP server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"[*] Server listening on {self.host}:{self.port}")

            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                client_thread.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            server_socket.close()

    def _handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        try:
            client_socket.send(HELP_SHOW_CLIENT.encode())
            while True:
                client_socket.send("> ".encode())
                data = client_socket.recv(8192).decode()
                if not data:
                    break
                try:
                    request_obj = json.loads(data)
                    request_obj = Request(**request_obj)
                    if not isinstance(request_obj, Request):
                        response = Response(status="error", error="Invalid request format") 
                        should_cache = False
                    else:
                        cacheable_methods = {"GET_PRODUCT", "GET_FLAG"}
                        should_cache = request_obj.method.upper() in cacheable_methods
                    session = request_obj.params["session"] if "session" in request_obj.params else None
                    request_obj.params.pop("session", None)  
                    if should_cache:
                        cached_response = self.request_cache.check_request(
                            method=request_obj.method,
                            params=request_obj.params,
                            ip_address=client_address[0],
                        )
                        if cached_response:
                            aes_key = json.loads(base64.b64decode(session)).get("aes_session_key")
                            if aes_key is None:
                                aes_key = get_random_bytes(32).hex()  # Fallback if session key is missing
                            response_decrypt = self.cryprosession.decrypt(cached_response, aes_key)
                            try:
                                response_decrypt = json.loads(response_decrypt)
                            except json.JSONDecodeError:
                                response_decrypt = {"b64": response_decrypt}
                            response = Response(status="ok", data=response_decrypt)
                            client_socket.send(json.dumps(response.__dict__).encode() + b"\n")
                            continue
                    response = self.dispatcher.dispatch(request_obj, session)
                    if should_cache and isinstance(request_obj, Request) and response.status == "ok":

                        aes_key = json.loads(base64.b64decode(session)).get("aes_session_key")
                        if aes_key is None:
                            aes_key = get_random_bytes(32).hex()  # Fallback if session key is missing
                        print(f"Cached: {response.data}")
                        response_encypted = self.cryprosession.encrypt(json.dumps(response.data), aes_key)
                        self.request_cache.add(
                            method=request_obj.method,
                            params=request_obj.params,
                            ip_address=client_address[0],
                            response=response_encypted
                        )
                    encrypted_response = response
                    client_socket.send(json.dumps(encrypted_response.__dict__).encode() + b"\n")

                except Exception as e:
                    if self.debug:
                        traceback.print_exc()
                    error_response = Response(
                        "error", error=f"Have an error in server"
                    )
                    client_socket.send(json.dumps(error_response.__dict__).encode())

        except Exception as e:
            if self.debug:
                print(f"[!] Error handling client {client_address}: {e}")
                traceback.print_exc()
        finally:
            client_socket.close()


if __name__ == "__main__":
    debug = "--debug" in sys.argv
    server = EncryptedProductServer(debug=debug)
    server.start()