import base64
from hashlib import md5
import json

from crypto import CryptoSession
from models import Response, Session
from storage import ProductStorage
from session import SessionManager
from secret import FLAG

class Dispatcher:
    def __init__(
        self,
        product_storage: ProductStorage,
        session_manager: SessionManager,
    ):
        self.products = product_storage
        self.sessions = session_manager

    def dispatch(self, request, session):
        """Route request to appropriate handler"""
        method = request.method.upper()
        params = request.params or {}

        handlers = {
            "LOGIN": self.handle_login,
            "GET_PRODUCT": self.handle_get_product,
            "LIST_PRODUCTS": self.handle_list_products,
            "GET_FLAG": self.handle_get_flag,
        }

        if method not in handlers:
            return Response(status="error", error=f"Unknown method: {method}")
        if session is None and method != "LOGIN":
            return Response(status="error", error="Please login first to obtain a session token")
        return handlers[method](params, session)


    def handle_login(self, params, session=None):
        """LOGIN username password"""
        try:
           
            username = params["username"] or ""
            password = params["password"] or ""
            if isinstance(username, str) or isinstance(password, str):
                username = username.strip()
                password = password.strip()
            if not username or not password:
                return Response(status="error", error="Missing username or password")
            if username == "admin":
                role = "admin"
                if password != FLAG:
                    return Response(status="error", error="Password wrong!")
            else:
                role = "user"
            
    
            aes_session_key = md5(password.encode()).digest().hex() # Derive AES session key from password
            session = self.sessions.create_session(username, role, aes_session_key)
            session_json = base64.b64encode(json.dumps({
                "session_id": session.session_id,
                "username": session.username,
                "role": session.role,
                "aes_session_key": session.aes_session_key,
                "session_hash": session.session_hash,
            }, sort_keys=True).encode()).decode()
            return Response(
                status="ok",
                data={"session": session_json},
            )
        except Exception as e:
            return Response(status="error", error=f"Login failed: {str(e)}")
   
    def handle_get_product(self, params, session):
        """GET_PRODUCT session product_name"""
        if session is None:
            return Response(status="error", error="Please login first to obtain a session token")
        session_json = json.loads(base64.b64decode(session))
        session = Session(**session_json)
        if not self.sessions.validate_session(session):
            return Response(status="error", error="Invalid session")
        product_name = params["product_name"] if "product_name" in params else None
        if isinstance(product_name, str):
            product_name = product_name.strip()
        if not product_name:
            return Response(status="error", error="Missing product_name")
        product = self.products.get_product(product_name)
        if not product:
            return Response(status="error", error="Product not found")
        if session.role != "admin" and product.owner != session.username:
            return Response(status="error", error="Access denied")
        description = CryptoSession().decrypt(product.description, session.aes_session_key)
        return Response(
            status="ok",
            data={
                "owner": product.owner,
                "name": product.name,
                "description": description,
            },
        )

    def handle_list_products(self, params, session=None):
        """LIST_PRODUCTS session_id"""
        if session is None:
            return Response(status="error", error="Please login first to obtain a session token")         
        session_json = json.loads(base64.b64decode(session))
        session = Session(**session_json)
        if not self.sessions.validate_session(session):
            return Response(status="error", error="Invalid session")
        products = self.products.list_products()
        product_list = [
            {
                "owner": p.owner,
                "name": p.name,
            }
            for p in products
        ]
        return Response(status="ok", data={"products": product_list})

    def handle_get_flag(self, params, session):
        """GET_FLAG session_id (admin only)"""
        if session is None:
            return Response(status="error", error="Please login first to obtain a session token")
        session_json = json.loads(base64.b64decode(session))
        session = Session(**session_json)
        if not self.sessions.validate_session(session):
            return Response(status="error", error="Invalid session")
        if session.role != "admin" or session.username != "admin":
            return Response(status="error", error="Admin access required")
        
        FLAG = self.products.get_product("FLAG").description if self.products.product_exists("FLAG") else None
        if not FLAG:
            return Response(status="error", error="Flag not found")
        FLAG = CryptoSession().decrypt(FLAG, session.aes_session_key)  # Decrypt the flag using the session's AES key
        return Response(status="ok", data={"flag": FLAG})
