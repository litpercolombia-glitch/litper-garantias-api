from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime, date, timedelta
from enum import Enum
import uuid
import os

from jose import JWTError, jwt
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, String, Text, DateTime, Date, Integer, Boolean, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secreto-cambiar")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class EstadoGarantia(str, Enum):
    pendiente = "pendiente"
    en_revision = "en_revision"
    aprobada = "aprobada"
    rechazada = "rechazada"
    resuelta = "resuelta"

class TipoProblema(str, Enum):
    danado = "danado"
    no_entregado = "no_entregado"
    incorrecto = "incorrecto"
    incompleto = "incompleto"
    calidad = "calidad"
    otro = "otro"

class Transportadora(str, Enum):
    interrapidisimo = "interrapidisimo"
    coordinadora = "coordinadora"
    envia = "envia"
    tcc = "tcc"
    servientrega = "servientrega"
    otro = "otro"

class RolUsuario(str, Enum):
    admin = "admin"
    supervisor = "supervisor"
    agente = "agente"

class UsuarioDB(Base):
    __tablename__ = "usuarios_admin"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    nombre = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    rol = Column(String(20), default="agente")
    activo = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class GarantiaDB(Base):
    __tablename__ = "garantias"
    id = Column(Integer, primary_key=True, index=True)
    numero_caso = Column(String(20), unique=True, index=True, nullable=False)
    nombre = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    telefono = Column(String(20), nullable=False)
    ciudad = Column(String(50), nullable=False)
    transportadora = Column(String(50), nullable=False)
    fecha_compra = Column(Date, nullable=True)
    producto_descripcion = Column(Text, nullable=True)
    tipo_problema = Column(String(50), nullable=False)
    descripcion = Column(Text, nullable=False)
    estado = Column(String(20), default="pendiente")
    division = Column(String(50), nullable=True)
    asignado_a = Column(Integer, ForeignKey("usuarios_admin.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notas = relationship("NotaGarantiaDB", back_populates="garantia", cascade="all, delete-orphan")
    evidencias = relationship("EvidenciaDB", back_populates="garantia", cascade="all, delete-orphan")

class NotaGarantiaDB(Base):
    __tablename__ = "garantias_notas"
    id = Column(Integer, primary_key=True, index=True)
    garantia_id = Column(Integer, ForeignKey("garantias.id"), nullable=False)
    usuario = Column(String(100), nullable=False)
    texto = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    garantia = relationship("GarantiaDB", back_populates="notas")

class EvidenciaDB(Base):
    __tablename__ = "garantias_evidencias"
    id = Column(Integer, primary_key=True, index=True)
    garantia_id = Column(Integer, ForeignKey("garantias.id"), nullable=False)
    nombre_archivo = Column(String(255), nullable=False)
    ruta_archivo = Column(String(500), nullable=False)
    tipo_archivo = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    garantia = relationship("GarantiaDB", back_populates="evidencias")

class UsuarioLogin(BaseModel):
    email: EmailStr
    password: str

class UsuarioCreate(BaseModel):
    email: EmailStr
    nombre: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8)
    rol: Optional[RolUsuario] = RolUsuario.agente

class UsuarioResponse(BaseModel):
    id: int
    email: str
    nombre: str
    rol: str
    activo: bool
    created_at: datetime
    last_login: Optional[datetime]
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    usuario: UsuarioResponse

class NotaCreate(BaseModel):
    texto: str = Field(..., min_length=1, max_length=1000)

class NotaResponse(BaseModel):
    id: int
    usuario: str
    texto: str
    created_at: datetime
    class Config:
        from_attributes = True

class EvidenciaResponse(BaseModel):
    id: int
    nombre_archivo: str
    ruta_archivo: str
    tipo_archivo: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

class GarantiaCreate(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    telefono: str = Field(..., min_length=7, max_length=20)
    ciudad: str = Field(..., min_length=2, max_length=50)
    transportadora: Transportadora
    fecha_compra: Optional[date] = None
    producto_descripcion: Optional[str] = Field(None, max_length=500)
    tipo_problema: TipoProblema
    descripcion: str = Field(..., min_length=20, max_length=2000)

class GarantiaUpdate(BaseModel):
    estado: Optional[EstadoGarantia] = None
    division: Optional[str] = None
    asignado_a: Optional[int] = None

class GarantiaResponse(BaseModel):
    id: int
    numero_caso: str
    nombre: str
    email: str
    telefono: str
    ciudad: str
    transportadora: str
    fecha_compra: Optional[date]
    producto_descripcion: Optional[str]
    tipo_problema: str
    descripcion: str
    estado: str
    division: Optional[str]
    asignado_a: Optional[int]
    created_at: datetime
    updated_at: datetime
    notas: List[NotaResponse] = []
    evidencias: List[EvidenciaResponse] = []
    class Config:
        from_attributes = True

class GarantiaListItem(BaseModel):
    id: int
    numero_caso: str
    nombre: str
    email: str
    telefono: str
    ciudad: str
    transportadora: str
    tipo_problema: str
    estado: str
    created_at: datetime
    evidencias_count: int = 0
    class Config:
        from_attributes = True

class PaginatedResponse(BaseModel):
    items: List[GarantiaListItem]
    total: int
    page: int
    page_size: int
    total_pages: int

class EstadisticasResponse(BaseModel):
    total: int
    pendientes: int
    en_revision: int
    aprobadas: int
    rechazadas: int
    resueltas: int
    hoy: int
    tasa_resolucion: float

class MessageResponse(BaseModel):
    message: str
    numero_caso: Optional[str] = None

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_token(data: dict, expires: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> UsuarioDB:
    payload = decode_token(credentials.credentials)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Token invalido")
    usuario = db.query(UsuarioDB).filter(UsuarioDB.email == email).first()
    if not usuario:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if not usuario.activo:
        raise HTTPException(status_code=403, detail="Usuario desactivado")
    return usuario

async def require_admin(user: UsuarioDB = Depends(get_current_user)) -> UsuarioDB:
    if user.rol != "admin":
        raise HTTPException(status_code=403, detail="Requiere admin")
    return user

async def require_supervisor(user: UsuarioDB = Depends(get_current_user)) -> UsuarioDB:
    if user.rol not in ["admin", "supervisor"]:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    return user

def generar_caso() -> str:
    return f"GAR-{datetime.now().strftime('%Y%m')}-{uuid.uuid4().hex[:4].upper()}"

TRANSP_LABELS = {"interrapidisimo": "Interrapidisimo", "coordinadora": "Coordinadora", "envia": "Envia", "tcc": "TCC", "servientrega": "Servientrega", "otro": "Otra"}
PROBLEMA_LABELS = {"danado": "Producto danado", "no_entregado": "No recibi mi pedido", "incorrecto": "Producto incorrecto", "incompleto": "Pedido incompleto", "calidad": "Problema de calidad", "otro": "Otro problema"}
ESTADO_LABELS = {"pendiente": "Pendiente", "en_revision": "En Revision", "aprobada": "Aprobada", "rechazada": "Rechazada", "resuelta": "Resuelta"}

app = FastAPI(title="Litper Garantias API", version="2.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.post("/api/auth/login", response_model=Token, tags=["Auth"])
async def login(creds: UsuarioLogin, db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.email == creds.email).first()
    if not user or not verify_password(creds.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if not user.activo:
        raise HTTPException(status_code=403, detail="Usuario desactivado")
    user.last_login = datetime.utcnow()
    db.commit()
    token = create_token({"sub": user.email, "user_id": user.id, "rol": user.rol, "nombre": user.nombre})
    return Token(access_token=token, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60, usuario=UsuarioResponse.model_validate(user))

@app.get("/api/auth/me", response_model=UsuarioResponse, tags=["Auth"])
async def get_profile(user: UsuarioDB = Depends(get_current_user)):
    return user

@app.post("/api/auth/usuarios", response_model=UsuarioResponse, status_code=201, tags=["Auth"])
async def create_user(data: UsuarioCreate, db: Session = Depends(get_db), admin: UsuarioDB = Depends(require_admin)):
    if db.query(UsuarioDB).filter(UsuarioDB.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email ya existe")
    user = UsuarioDB(email=data.email, nombre=data.nombre, hashed_password=hash_password(data.password), rol=data.rol.value)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.get("/api/auth/usuarios", response_model=List[UsuarioResponse], tags=["Auth"])
async def list_users(db: Session = Depends(get_db), admin: UsuarioDB = Depends(require_admin)):
    return db.query(UsuarioDB).order_by(UsuarioDB.created_at.desc()).all()

@app.patch("/api/auth/usuarios/{id}/toggle", tags=["Auth"])
async def toggle_user(id: int, db: Session = Depends(get_db), admin: UsuarioDB = Depends(require_admin)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="No encontrado")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes desactivarte")
    user.activo = not user.activo
    db.commit()
    return {"message": f"Usuario {'activado' if user.activo else 'desactivado'}"}

@app.post("/api/garantias", response_model=MessageResponse, status_code=201, tags=["Publico"])
async def crear_garantia(data: GarantiaCreate, db: Session = Depends(get_db)):
    numero = generar_caso()
    while db.query(GarantiaDB).filter(GarantiaDB.numero_caso == numero).first():
        numero = generar_caso()
    g = GarantiaDB(numero_caso=numero, nombre=data.nombre, email=data.email, telefono=data.telefono, ciudad=data.ciudad, transportadora=data.transportadora.value, fecha_compra=data.fecha_compra, producto_descripcion=data.producto_descripcion, tipo_problema=data.tipo_problema.value, descripcion=data.descripcion)
    db.add(g)
    db.commit()
    return MessageResponse(message="Solicitud creada", numero_caso=numero)

@app.get("/api/garantias/consultar/{numero}", tags=["Publico"])
async def consultar_estado(numero: str, db: Session = Depends(get_db)):
    g = db.query(GarantiaDB).filter(GarantiaDB.numero_caso == numero).first()
    if not g:
        raise HTTPException(status_code=404, detail="No encontrada")
    return {"numero_caso": g.numero_caso, "estado": g.estado, "estado_label": ESTADO_LABELS.get(g.estado), "tipo_problema": PROBLEMA_LABELS.get(g.tipo_problema), "fecha_solicitud": g.created_at.strftime("%Y-%m-%d"), "ultima_actualizacion": g.updated_at.strftime("%Y-%m-%d %H:%M")}

@app.get("/api/admin/garantias", response_model=PaginatedResponse, tags=["Admin"])
async def list_garantias(page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), estado: Optional[EstadoGarantia] = None, transportadora: Optional[Transportadora] = None, q: Optional[str] = None, db: Session = Depends(get_db), user: UsuarioDB = Depends(get_current_user)):
    query = db.query(GarantiaDB)
    if estado:
        query = query.filter(GarantiaDB.estado == estado.value)
    if transportadora:
        query = query.filter(GarantiaDB.transportadora == transportadora.value)
    if q:
        t = f"%{q}%"
        query = query.filter((GarantiaDB.nombre.ilike(t)) | (GarantiaDB.email.ilike(t)) | (GarantiaDB.telefono.ilike(t)) | (GarantiaDB.numero_caso.ilike(t)))
    total = query.count()
    items = query.order_by(GarantiaDB.created_at.desc()).offset((page-1)*size).limit(size).all()
    return PaginatedResponse(items=[GarantiaListItem(id=g.id, numero_caso=g.numero_caso, nombre=g.nombre, email=g.email, telefono=g.telefono, ciudad=g.ciudad, transportadora=TRANSP_LABELS.get(g.transportadora, g.transportadora), tipo_problema=PROBLEMA_LABELS.get(g.tipo_problema, g.tipo_problema), estado=g.estado, created_at=g.created_at, evidencias_count=len(g.evidencias)) for g in items], total=total, page=page, page_size=size, total_pages=(total+size-1)//size)

@app.get("/api/admin/garantias/stats", response_model=EstadisticasResponse, tags=["Admin"])
async def get_stats(db: Session = Depends(get_db), user: UsuarioDB = Depends(get_current_user)):
    total = db.query(GarantiaDB).count()
    pend = db.query(GarantiaDB).filter(GarantiaDB.estado == "pendiente").count()
    rev = db.query(GarantiaDB).filter(GarantiaDB.estado == "en_revision").count()
    apr = db.query(GarantiaDB).filter(GarantiaDB.estado == "aprobada").count()
    rech = db.query(GarantiaDB).filter(GarantiaDB.estado == "rechazada").count()
    res = db.query(GarantiaDB).filter(GarantiaDB.estado == "resuelta").count()
    hoy = db.query(GarantiaDB).filter(func.date(GarantiaDB.created_at) == date.today()).count()
    tasa = ((apr + res) / total * 100) if total > 0 else 0
    return EstadisticasResponse(total=total, pendientes=pend, en_revision=rev, aprobadas=apr, rechazadas=rech, resueltas=res, hoy=hoy, tasa_resolucion=round(tasa, 1))

@app.get("/api/admin/garantias/{id}", response_model=GarantiaResponse, tags=["Admin"])
async def get_garantia(id: int, db: Session = Depends(get_db), user: UsuarioDB = Depends(get_current_user)):
    g = db.query(GarantiaDB).filter(GarantiaDB.id == id).first()
    if not g:
        raise HTTPException(status_code=404, detail="No encontrada")
    return g

@app.patch("/api/admin/garantias/{id}", response_model=GarantiaResponse, tags=["Admin"])
async def update_garantia(id: int, data: GarantiaUpdate, db: Session = Depends(get_db), user: UsuarioDB = Depends(get_current_user)):
    g = db.query(GarantiaDB).filter(GarantiaDB.id == id).first()
    if not g:
        raise HTTPException(status_code=404, detail="No encontrada")
    old_estado = g.estado
    if data.estado:
        g.estado = data.estado.value
    if data.division:
        g.division = data.division
    if data.asignado_a is not None:
        g.asignado_a = data.asignado_a
    if data.estado and old_estado != data.estado.value:
        nota = NotaGarantiaDB(garantia_id=g.id, usuario=user.nombre, texto=f"Estado: {ESTADO_LABELS.get(data.estado.value)}")
        db.add(nota)
    db.commit()
    db.refresh(g)
    return g

@app.post("/api/admin/garantias/{id}/notas", response_model=NotaResponse, status_code=201, tags=["Admin"])
async def add_nota(id: int, data: NotaCreate, db: Session = Depends(get_db), user: UsuarioDB = Depends(get_current_user)):
    g = db.query(GarantiaDB).filter(GarantiaDB.id == id).first()
    if not g:
        raise HTTPException(status_code=404, detail="No encontrada")
    n = NotaGarantiaDB(garantia_id=id, usuario=user.nombre, texto=data.texto)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n

@app.delete("/api/admin/garantias/{id}", tags=["Admin"])
async def delete_garantia(id: int, db: Session = Depends(get_db), user: UsuarioDB = Depends(require_supervisor)):
    g = db.query(GarantiaDB).filter(GarantiaDB.id == id).first()
    if not g:
        raise HTTPException(status_code=404, detail="No encontrada")
    db.delete(g)
    db.commit()
    return {"message": "Eliminada"}

@app.get("/health", tags=["Sistema"])
async def health():
    return {"status": "ok", "service": "Litper Garantias", "version": "2.0.0"}
