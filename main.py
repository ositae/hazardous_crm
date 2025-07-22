from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import (
    create_engine, Column, Integer, String, ForeignKey, DateTime, Enum, and_, or_
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
import enum
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt

# --- Configuration ---
DATABASE_URL = "sqlite:///./hazardous_crm.db"
SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_ME"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Enums ---
class CompanyType(str, enum.Enum):
    PRIMARY = "Primary"
    CLIENT = "Client"
    MISCELLANEOUS = "Miscellaneous"

class UserRole(str, enum.Enum):
    ADMIN = "Admin"
    DISPATCHER = "Dispatcher"
    VIEWER = "Viewer"

class AuditAction(str, enum.Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    company_type = Column(Enum(CompanyType), default=CompanyType.MISCELLANEOUS)
    address = Column(String, nullable=True)
    contact_email = Column(String, nullable=True)
    deliveries = relationship("Delivery", back_populates="company")

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    hazard_class = Column(String, nullable=False)
    description = Column(String, nullable=True)
    deliveries = relationship("Delivery", back_populates="product")

class Delivery(Base):
    __tablename__ = "deliveries"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer, nullable=False)
    delivery_date = Column(DateTime, default=datetime.utcnow)
    notes = Column(String, nullable=True)

    company = relationship("Company", back_populates="deliveries")
    product = relationship("Product", back_populates="deliveries")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    delivery_id = Column(Integer, ForeignKey("deliveries.id"), nullable=True)
    action = Column(Enum(AuditAction))
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail = Column(String, nullable=True)

    user = relationship("User")
    delivery = relationship("Delivery")

# --- Pydantic Schemas ---
# User Schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.VIEWER

class UserRead(UserBase):
    id: int
    class Config:
        orm_mode = True

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Company Schemas
class CompanyBase(BaseModel):
    name: str = Field(..., example="ACME Corp")
    company_type: CompanyType
    address: Optional[str]
    contact_email: Optional[EmailStr]

class CompanyCreate(CompanyBase):
    pass

class CompanyRead(CompanyBase):
    id: int
    class Config:
        orm_mode = True

# Product Schemas
class ProductBase(BaseModel):
    name: str = Field(..., example="Flammable Liquid")
    hazard_class: str = Field(..., example="3 - Flammable Liquids")
    description: Optional[str]

class ProductCreate(ProductBase):
    pass

class ProductRead(ProductBase):
    id: int
    class Config:
        orm_mode = True

# Delivery Schemas
class DeliveryBase(BaseModel):
    company_id: int
    product_id: int
    quantity: int = Field(..., gt=0)
    delivery_date: Optional[datetime]
    notes: Optional[str]

class DeliveryCreate(DeliveryBase):
    pass

class DeliveryUpdate(BaseModel):
    quantity: Optional[int] = Field(None, gt=0)
    delivery_date: Optional[datetime]
    notes: Optional[str]

class DeliveryRead(DeliveryBase):
    id: int
    delivery_date: datetime
    company: CompanyRead
    product: ProductRead
    class Config:
        orm_mode = True

# AuditLog Read Schema
class AuditLogRead(BaseModel):
    id: int
    user_id: int
    delivery_id: Optional[int]
    action: AuditAction
    timestamp: datetime
    detail: Optional[str]
    class Config:
        orm_mode = True

# --- Utility Functions ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return TokenData(username=username)
    except jwt.PyJWTError:
        return None

def get_user(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# Dependency to get current user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())) -> User:
    token_data = decode_access_token(token)
    if not token_data or not token_data.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user(db, token_data.username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Role-based dependencies
def require_role(required_roles: List[UserRole]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role",
            )
        return current_user
    return role_checker

def log_audit(db: Session, user_id: int, action: AuditAction, delivery: Optional[Delivery], detail: str = ""):
    audit = AuditLog(
        user_id=user_id,
        delivery_id=delivery.id if delivery else None,
        action=action,
        timestamp=datetime.utcnow(),
        detail=detail
    )
    db.add(audit)
    db.commit()

# --- Application ---
app = FastAPI(title="Hazardous Products CRM with Auth & Audit")

Base.metadata.create_all(bind=engine)

# --- Authentication Routes ---
@app.post("/users/", response_model=UserRead, status_code=201)
def create_user(user_create: UserCreate, db: Session = Depends(lambda: SessionLocal()),
                current_user: User = Depends(require_role([UserRole.ADMIN]))):
    # Only Admin can create users
    user = get_user(db, user_create.username)
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user_create.password)
    db_user = User(
        username=user_create.username,
        email=user_create.email,
        hashed_password=hashed_password,
        role=user_create.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(lambda: SessionLocal())):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=UserRead)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- Companies ---
@app.post("/companies/", response_model=CompanyRead)
def create_company(company: CompanyCreate, db: Session = Depends(lambda: SessionLocal()),
                   current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.DISPATCHER]))):
    db_company = db.query(Company).filter(Company.name == company.name).first()
    if db_company:
        raise HTTPException(status_code=400, detail="Company already registered")
    new_company = Company(**company.dict())
    db.add(new_company)
    db.commit()
    db.refresh(new_company)
    return new_company

@app.get("/companies/", response_model=List[CompanyRead])
def read_companies(
    skip: int = 0,
    limit: int = 20,
    name: Optional[str] = Query(None, description="Filter by name (substring)"),
    company_type: Optional[CompanyType] = Query(None, description="Filter by company type"),
    db: Session = Depends(lambda: SessionLocal()),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Company)
    if name:
        query = query.filter(Company.name.ilike(f"%{name}%"))
    if company_type:
        query = query.filter(Company.company_type == company_type)
    companies = query.offset(skip).limit(limit).all()
    return companies

@app.get("/companies/{company_id}", response_model=CompanyRead)
def read_company(company_id: int, db: Session = Depends(lambda: SessionLocal()), current_user: User = Depends(get_current_user)):
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

# --- Products ---
@app.post("/products/", response_model=ProductRead)
def create_product(product: ProductCreate, db: Session = Depends(lambda: SessionLocal()),
                   current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.DISPATCHER]))):
    db_product = db.query(Product).filter(Product.name == product.name).first()
    if db_product:
        raise HTTPException(status_code=400, detail="Product already exists")
    new_product = Product(**product.dict())
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return new_product

@app.get("/products/", response_model=List[ProductRead])
def read_products(
    skip: int = 0,
    limit: int = 20,
    search: Optional[str] = Query(None, description="Search by name or hazard class"),
    db: Session = Depends(lambda: SessionLocal()),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Product)
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(or_(Product.name.ilike(search_pattern), Product.hazard_class.ilike(search_pattern)))
    products = query.offset(skip).limit(limit).all()
    return products

@app.get("/products/{product_id}", response_model=ProductRead)
def read_product(product_id: int, db: Session = Depends(lambda: SessionLocal()), current_user: User = Depends(get_current_user)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

# --- Deliveries ---
@app.post("/deliveries/", response_model=DeliveryRead, status_code=201)
def create_delivery(delivery: DeliveryCreate, db: Session = Depends(lambda: SessionLocal()),
                    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.DISPATCHER]))):
    company = db.query(Company).filter(Company.id == delivery.company_id).first()
    if not company:
        raise HTTPException(status_code=400, detail="Invalid company_id")
    product = db.query(Product).filter(Product.id == delivery.product_id).first()
    if not product:
        raise HTTPException(status_code=400, detail="Invalid product_id")
    new_delivery = Delivery(
        company_id=delivery.company_id,
        product_id=delivery.product_id,
        quantity=delivery.quantity,
        delivery_date=delivery.delivery_date or datetime.utcnow(),
        notes=delivery.notes
    )
    db.add(new_delivery)
    db.commit()
    db.refresh(new_delivery)
    # Audit log
    log_audit(db, current_user.id, AuditAction.CREATE, new_delivery, detail=f"Created delivery with quantity {new_delivery.quantity}")
    return new_delivery

@app.get("/deliveries/", response_model=List[DeliveryRead])
def read_deliveries(
    skip: int = 0,
    limit: int = 20,
    company_id: Optional[int] = Query(None, description="Filter by company ID"),
    product_id: Optional[int] = Query(None, description="Filter by product ID"),
    start_date: Optional[datetime] = Query(None, description="Filter deliveries from this date (inclusive)"),
    end_date: Optional[datetime] = Query(None, description="Filter deliveries until this date (inclusive)"),
    db: Session = Depends(lambda: SessionLocal()),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Delivery)
    if company_id:
        query = query.filter(Delivery.company_id == company_id)
    if product_id:
        query = query.filter(Delivery.product_id == product_id)
    if start_date and end_date:
        query = query.filter(Delivery.delivery_date.between(start_date, end_date))
    elif start_date:
        query = query.filter(Delivery.delivery_date >= start_date)
    elif end_date:
        query = query.filter(Delivery.delivery_date <= end_date)
    deliveries = query.offset(skip).limit(limit).all()
    return deliveries

@app.get("/deliveries/{delivery_id}", response_model=DeliveryRead)
def read_delivery(delivery_id: int, db: Session = Depends(lambda: SessionLocal()), current_user: User = Depends(get_current_user)):
    delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found")
    return delivery

@app.put("/deliveries/{delivery_id}", response_model=DeliveryRead)
def update_delivery(delivery_id: int, delivery_update: DeliveryUpdate, db: Session = Depends(lambda: SessionLocal()),
                    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.DISPATCHER]))):
    delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found")
    updated_fields = []
    if delivery_update.quantity is not None:
        delivery.quantity = delivery_update.quantity
        updated_fields.append(f"quantity={delivery_update.quantity}")
    if delivery_update.delivery_date is not None:
        delivery.delivery_date = delivery_update.delivery_date
        updated_fields.append(f"delivery_date={delivery_update.delivery_date.isoformat()}")
    if delivery_update.notes is not None:
        delivery.notes = delivery_update.notes
        updated_fields.append(f"notes='{delivery_update.notes}'")
    db.commit()
    db.refresh(delivery)
    log_audit(db, current_user.id, AuditAction.UPDATE, delivery, detail="Updated fields: " + ", ".join(updated_fields))
    return delivery

@app.delete("/deliveries/{delivery_id}", status_code=204)
def delete_delivery(delivery_id: int, db: Session = Depends(lambda: SessionLocal()),
                    current_user: User = Depends(require_role([UserRole.ADMIN]))):
    delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found")
    db.delete(delivery)
    db.commit()
    log_audit(db, current_user.id, AuditAction.DELETE, delivery, detail="Deleted delivery record")
    return

# --- Audit Logs ---
@app.get("/audit-logs/", response_model=List[AuditLogRead])
def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = Query(None),
    delivery_id: Optional[int] = Query(None),
    action: Optional[AuditAction] = Query(None),
    db: Session = Depends(lambda: SessionLocal()),
    current_user: User = Depends(require_role([UserRole.ADMIN]))
):
    # Only admin can view audit logs
    query = db.query(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if delivery_id:
        query = query.filter(AuditLog.delivery_id == delivery_id)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs