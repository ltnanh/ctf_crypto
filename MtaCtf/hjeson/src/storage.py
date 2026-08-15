import secrets
from datetime import datetime
from typing import Optional, Dict, List
from crypto import CryptoSession
from models import Product



class ProductStorage:
    def __init__(self):
        self.products: Dict[str, Product] = {}
        self.product_count = 0

    def create_product(
        self,
        owner: str,
        name: str,
        description: str,
    ) -> Product:
        if name in self.products:
            raise ValueError("Product with this name already exists")
        
        product = Product(
            owner=owner,
            name=name,
            description=description,
        )
        self.products[name] = product
        return product

    def get_product(self, product_name: str) -> Optional[Product]:
        return self.products.get(product_name)

    def delete_product(self, product_name: str) -> bool:
        if product_name in self.products:
            del self.products[product_name]
            return True
        return False

    def list_products(self) -> List[Product]:
        return list(self.products.values())

    def list_user_products(self, username: str) -> List[Product]:
        return [p for p in self.products.values() if p.owner == username]

    def product_exists(self, product_name: str) -> bool:
        return product_name in self.products

    def get_product_owner(self, product_name: str) -> Optional[str]:
        product = self.get_product(product_name)
        return product.owner if product else None
