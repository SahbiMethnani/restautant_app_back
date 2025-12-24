from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Literal, Optional
from datetime import datetime, timedelta
import jwt
import json
import os
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, and_
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.sql import func
from datetime import date as date_module
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import bcrypt


# Configuration du logging sécurisé
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Charger les variables d'environnement
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

# Variables d'environnement avec validation
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY :#or len(SECRET_KEY) < 32:
    raise ValueError("SECRET_KEY doit être définie et faire au moins 32 caractères")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

if not ADMIN_USERNAME or not ADMIN_PASSWORD_HASH:
    raise ValueError("ADMIN_USERNAME et ADMIN_PASSWORD_HASH doivent être définis")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL doit être définie")

# Configuration de l'environnement
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT == "production"

# Configuration des origines CORS autorisées
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

# Configuration du hachage de mots de passe (bcrypt)

# Configuration JWT
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Configuration PostgreSQL avec SSL
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args={"sslmode": "require"} if IS_PRODUCTION else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèles SQLAlchemy
class PlatDB(Base):
    __tablename__ = "plats"
    
    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String(255), nullable=False)
    description = Column(Text)
    prix = Column(Float, nullable=False)
    categorie = Column(String(100), nullable=False)
    image_url = Column(String(500), nullable=True)

class CommandeDB(Base):
    __tablename__ = "commandes"
    
    id = Column(Integer, primary_key=True, index=True)
    table_num = Column(Integer, nullable=False)
    items = Column(Text, nullable=False)
    status = Column(String(50), default="en_attente")
    created_at = Column(DateTime, server_default=func.now())
    total = Column(Float)

class CategorieImageDB(Base):
    __tablename__ = "categorie_images"
    
    id = Column(Integer, primary_key=True, index=True)
    categorie = Column(String(100), nullable=False, unique=True)
    image_base64 = Column(Text, nullable=True)

class ConfigDB(Base):
    __tablename__ = "config"
    
    id = Column(Integer, primary_key=True, index=True)
    nombre_tables = Column(Integer, default=10)

# Initialisation de l'application
app = FastAPI(
    title="Restaurant Ordering API",
    version="2.0.0",
    docs_url="/docs" if not IS_PRODUCTION else None,  # Désactiver docs en prod
    redoc_url="/redoc" if not IS_PRODUCTION else None
)

# Configuration du rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

security = HTTPBearer()

# Middleware de sécurité
if IS_PRODUCTION:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost").split(",")
    )

# Configuration CORS sécurisée
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=3600
)
def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt"""
    password_bytes = password.encode('utf-8')[:72]  # Limiter à 72 bytes
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe avec bcrypt"""
    try:
        password_bytes = plain_password.encode('utf-8')[:72]
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception as e:
        logger.error(f"Erreur vérification mot de passe: {str(e)}")
        return False

# Modèles Pydantic avec validation renforcée
class ItemCommande(BaseModel):
    plat_id: int = Field(..., gt=0, description="ID du plat")
    quantite: int = Field(..., gt=0, le=100, description="Quantité (max 100)")

class Plat(BaseModel):
    id: Optional[int] = None
    nom: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., max_length=1000)
    prix: float = Field(..., gt=0, le=10000)
    categorie: str = Field(..., min_length=1, max_length=100)
    image_url: Optional[str] = Field(None, max_length=500)
    
    @validator('image_url')
    def validate_image_url(cls, v):
        if v and not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL doit commencer par http:// ou https://')
        return v

class Commande(BaseModel):
    id: Optional[int] = None
    table_num: int = Field(..., gt=0, le=200)
    items: List[ItemCommande] = Field(..., min_items=1, max_items=50)
    status: Literal["en_attente", "preparation", "prete"] = "en_attente"
    created_at: Optional[datetime] = None
    total: Optional[float] = None

class AdminLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)

class CommandeUpdate(BaseModel):
    status: Literal["en_attente", "preparation", "prete"]

class ConfigUpdate(BaseModel):
    nombre_tables: int = Field(..., ge=1, le=200)

class CategorieImage(BaseModel):
    categorie: str = Field(..., min_length=1, max_length=100)
    image_base64: str = Field(..., max_length=5_000_000)  # ~3.5MB max
    
    @validator('image_base64')
    def validate_base64_image(cls, v):
        if not v.startswith('data:image/'):
            raise ValueError('Format image invalide. Doit commencer par data:image/')
        allowed_formats = ['jpeg', 'jpg', 'png', 'webp', 'gif']
        if not any(f'image/{fmt}' in v[:50] for fmt in allowed_formats):
            raise ValueError(f'Format image non autorisé. Formats acceptés: {", ".join(allowed_formats)}')
        return v

# Dependency pour obtenir la session DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialisation de la base de données
def init_db():
    logger.info("Initialisation de la base de données...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Tables créées avec succès")
        
        db = SessionLocal()
        try:
            plats_count = db.query(PlatDB).count()
            logger.info(f"Nombre de plats en base: {plats_count}")
            
            if plats_count == 0:
                sample_plats = [
                    PlatDB(nom="Salade César", description="Salade verte, croûtons, parmesan, sauce césar", prix=12.50, categorie="Entrées"),
                    PlatDB(nom="Soupe du jour", description="Soupe préparée avec les légumes de saison", prix=8.00, categorie="Entrées"),
                    PlatDB(nom="Steak frites", description="Steak de bœuf grillé avec frites maison", prix=22.00, categorie="Plats"),
                    PlatDB(nom="Saumon grillé", description="Saumon grillé avec légumes de saison", prix=24.00, categorie="Plats"),
                    PlatDB(nom="Pizza Margherita", description="Tomate, mozzarella, basilic", prix=16.00, categorie="Plats"),
                    PlatDB(nom="Tiramisu", description="Dessert italien traditionnel", prix=7.50, categorie="Desserts"),
                    PlatDB(nom="Tarte aux pommes", description="Tarte maison aux pommes", prix=6.50, categorie="Desserts"),
                    PlatDB(nom="Coca Cola", description="Boisson gazeuse 33cl", prix=3.50, categorie="Boissons"),
                    PlatDB(nom="Eau minérale", description="Eau plate ou pétillante 50cl", prix=2.50, categorie="Boissons"),
                ]
                db.add_all(sample_plats)
                db.commit()
                logger.info(f"{len(sample_plats)} plats insérés")
            
            config_exists = db.query(ConfigDB).first()
            if not config_exists:
                default_config = ConfigDB(nombre_tables=10)
                db.add(default_config)
                db.commit()
                logger.info("Configuration par défaut créée")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation: {str(e)}")
        raise

def create_access_token(data: dict) -> str:
    """Crée un token JWT avec expiration"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Vérifie et décode le token JWT"""
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        
        if payload.get("role") != "admin":
            logger.warning(f"Tentative d'accès avec rôle invalide: {payload.get('role')}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès non autorisé"
            )
        
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expiré utilisé")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expiré"
        )
    except jwt.InvalidTokenError:
        logger.warning("Token invalide utilisé")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide"
        )

def calculate_total(items: List[ItemCommande], db: Session) -> float:
    """Calcule le total d'une commande"""
    total = 0.0
    for item in items:
        plat = db.query(PlatDB).filter(PlatDB.id == item.plat_id).first()
        if not plat:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Un ou plusieurs plats non trouvés"
            )
        total += plat.prix * item.quantite
    return round(total, 2)

# Routes publiques
@app.get("/")
@limiter.limit("60/minute")
def root(request: Request):
    return {
        "message": "API Restaurant - Service de commandes",
        "version": "2.0.0",
        "status": "operational"
    }

@app.get("/health")
@limiter.limit("30/minute")
def health_check(request: Request, db: Session = Depends(get_db)):
    """Vérification de santé de l'API"""
    try:
        db.execute("SELECT 1")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "unhealthy", "database": "disconnected"}

@app.get("/menu", response_model=List[Plat])
@limiter.limit("100/minute")
def get_menu(request: Request, db: Session = Depends(get_db)):
    """Récupère le menu complet"""
    try:
        plats = db.query(PlatDB).order_by(PlatDB.categorie, PlatDB.nom).all()
        return [
            Plat(
                id=plat.id,
                nom=plat.nom,
                description=plat.description,
                prix=plat.prix,
                categorie=plat.categorie,
                image_url=plat.image_url
            )
            for plat in plats
        ]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du menu: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération du menu"
        )

@app.post("/commande", response_model=dict)
@limiter.limit("20/minute")
def create_commande(request: Request, commande: Commande, db: Session = Depends(get_db)):
    """Crée une nouvelle commande"""
    try:
        # Vérifier le numéro de table
        config = db.query(ConfigDB).first()
        max_tables = config.nombre_tables if config else 10
        
        if commande.table_num > max_tables:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Numéro de table invalide (max: {max_tables})"
            )
        
        # Calculer le total
        total = calculate_total(commande.items, db)
        
        new_commande = CommandeDB(
            table_num=commande.table_num,
            items=json.dumps([item.dict() for item in commande.items]),
            status="en_attente",
            total=total
        )
        
        db.add(new_commande)
        db.commit()
        db.refresh(new_commande)
        
        logger.info(f"Commande créée: ID={new_commande.id}, Table={commande.table_num}, Total={total}")
        
        return {
            "message": "Commande créée avec succès",
            "commande_id": new_commande.id,
            "status": "en_attente",
            "total": total
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la création de commande: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la création de la commande"
        )

@app.get("/commande/{table_num}", response_model=Optional[Commande])
@limiter.limit("60/minute")
def get_commande_by_table(request: Request, table_num: int, db: Session = Depends(get_db)):
    """Récupère la dernière commande d'une table"""
    try:
        if table_num <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Numéro de table invalide"
            )
        
        commande = db.query(CommandeDB).filter(
            CommandeDB.table_num == table_num
        ).order_by(CommandeDB.created_at.desc()).first()
        
        if not commande:
            return None
        
        items = [ItemCommande(**item) for item in json.loads(commande.items)]
        
        return Commande(
            id=commande.id,
            table_num=commande.table_num,
            items=items,
            status=commande.status,
            created_at=commande.created_at,
            total=commande.total
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de commande: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération de la commande"
        )

# Routes d'administration
@app.post("/admin/login")
@limiter.limit("5/minute")
def admin_login(request: Request, credentials: AdminLogin):
    """Authentification administrateur avec rate limiting"""
    try:
        # Vérification username
        if credentials.username != ADMIN_USERNAME:
            logger.warning(f"Tentative de connexion avec username invalide: {credentials.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Identifiants incorrects"
            )
        
        # Vérification password
        if not verify_password(credentials.password, ADMIN_PASSWORD_HASH):
            logger.warning(f"Tentative de connexion avec mot de passe invalide pour: {credentials.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Identifiants incorrects"
            )
        
        # Création du token
        token = create_access_token({
            "username": credentials.username,
            "role": "admin"
        })
        
        logger.info(f"Connexion admin réussie: {credentials.username}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la connexion admin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la connexion"
        )

@app.get("/admin/commandes", response_model=List[Commande])
@limiter.limit("100/minute")
def get_all_commandes(
    request: Request,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Récupère toutes les commandes (admin uniquement)"""
    try:
        commandes_db = db.query(CommandeDB).order_by(CommandeDB.created_at.desc()).all()
        
        commandes = []
        for commande in commandes_db:
            items = [ItemCommande(**item) for item in json.loads(commande.items)]
            commandes.append(Commande(
                id=commande.id,
                table_num=commande.table_num,
                items=items,
                status=commande.status,
                created_at=commande.created_at,
                total=commande.total
            ))
        
        return commandes
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des commandes: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des commandes"
        )

@app.put("/admin/commande/{commande_id}")
@limiter.limit("60/minute")
def update_commande_status(
    request: Request,
    commande_id: int,
    update_data: CommandeUpdate,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Met à jour le statut d'une commande (admin uniquement)"""
    try:
        commande = db.query(CommandeDB).filter(CommandeDB.id == commande_id).first()
        
        if not commande:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ressource non trouvée"
            )
        
        commande.status = update_data.status
        db.commit()
        
        logger.info(f"Commande {commande_id} mise à jour: statut={update_data.status}")
        
        return {"message": "Statut mis à jour avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de commande: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la mise à jour"
        )

@app.get("/admin/stats")
@limiter.limit("60/minute")
def get_admin_stats(
    request: Request,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Statistiques pour l'admin"""
    try:
        today = date_module.today()
        
        total_commandes = db.query(CommandeDB).filter(
            func.date(CommandeDB.created_at) == today
        ).count()
        
        en_attente = db.query(CommandeDB).filter(
            and_(func.date(CommandeDB.created_at) == today, CommandeDB.status == "en_attente")
        ).count()
        
        preparation = db.query(CommandeDB).filter(
            and_(func.date(CommandeDB.created_at) == today, CommandeDB.status == "preparation")
        ).count()
        
        prete = db.query(CommandeDB).filter(
            and_(func.date(CommandeDB.created_at) == today, CommandeDB.status == "prete")
        ).count()
        
        chiffre_affaires = db.query(func.sum(CommandeDB.total)).filter(
            func.date(CommandeDB.created_at) == today
        ).scalar() or 0
        
        return {
            "total_commandes_today": total_commandes,
            "en_attente": en_attente,
            "preparation": preparation,
            "prete": prete,
            "chiffre_affaires_today": round(chiffre_affaires, 2)
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des statistiques"
        )

# Routes CRUD pour les plats (admin)
@app.post("/admin/plat", response_model=Plat, status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
def create_plat(
    request: Request,
    plat: Plat,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Ajouter un nouveau plat (admin uniquement)"""
    try:
        new_plat = PlatDB(
            nom=plat.nom,
            description=plat.description,
            prix=plat.prix,
            categorie=plat.categorie,
            image_url=plat.image_url
        )
        db.add(new_plat)
        db.commit()
        db.refresh(new_plat)
        
        logger.info(f"Plat créé: {new_plat.nom}")
        
        return Plat(
            id=new_plat.id,
            nom=new_plat.nom,
            description=new_plat.description,
            prix=new_plat.prix,
            categorie=new_plat.categorie,
            image_url=new_plat.image_url
        )
    except Exception as e:
        logger.error(f"Erreur lors de la création de plat: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la création du plat"
        )

@app.put("/admin/plat/{plat_id}", response_model=Plat)
@limiter.limit("30/minute")
def update_plat(
    request: Request,
    plat_id: int,
    plat: Plat,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Modifier un plat (admin uniquement)"""
    try:
        db_plat = db.query(PlatDB).filter(PlatDB.id == plat_id).first()
        
        if not db_plat:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ressource non trouvée"
            )
        
        db_plat.nom = plat.nom
        db_plat.description = plat.description
        db_plat.prix = plat.prix
        db_plat.categorie = plat.categorie
        db_plat.image_url = plat.image_url
        
        db.commit()
        db.refresh(db_plat)
        
        logger.info(f"Plat mis à jour: {db_plat.nom}")
        
        return Plat(
            id=db_plat.id,
            nom=db_plat.nom,
            description=db_plat.description,
            prix=db_plat.prix,
            categorie=db_plat.categorie,
            image_url=db_plat.image_url
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de plat: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la mise à jour du plat"
        )

@app.delete("/admin/plat/{plat_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("30/minute")
def delete_plat(
    request: Request,
    plat_id: int,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    """Supprimer un plat (admin uniquement)"""
    try:
        db_plat = db.query(PlatDB).filter(PlatDB.id == plat_id).first()
        
        if not db_plat:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ressource non trouvée"
            )
        
        db.delete(db_plat)
        db.commit()
        
        logger.info(f"Plat supprimé: ID={plat_id}")
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de plat: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la suppression du plat"
        )

# Routes pour les images de catégories
@app.get("/categories/images")
@limiter.limit("100/minute")
def get_categories_images(request: Request, db: Session = Depends(get_db)):
    """Récupérer les images des catégories (PUBLIC)"""
    try:
        images = db.query(CategorieImageDB).all()
        return {cat.categorie: cat.image_base64 for cat in images}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des images: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des images"
        )

@app.post("/admin/categorie/image")
@limiter.limit("10/minute")
def upload_categorie_image(
    request: Request,
    data: CategorieImage,
    admin: dict = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    existing = db.query(CategorieImageDB).filter(CategorieImageDB.categorie == data.categorie).first()
    
    if existing:
        existing.image_base64 = data.image_base64
    else:
        new_image = CategorieImageDB(categorie=data.categorie, image_base64=data.image_base64)
        db.add(new_image)
    
    db.commit()
    return {"message": f"Image de la catégorie '{data.categorie}' sauvegardée"}
@app.delete("/admin/categorie/image/{categorie}")
def delete_categorie_image(categorie: str, admin: dict = Depends(verify_admin_token), db: Session = Depends(get_db)):
    """Supprimer l'image d'une catégorie"""
    image = db.query(CategorieImageDB).filter(CategorieImageDB.categorie == categorie).first()
    
    if image:
        db.delete(image)
        db.commit()
    
    return {"message": f"Image de la catégorie '{categorie}' supprimée"}

# Routes pour la configuration du restaurant
@app.get("/config/tables")
def get_table_config(db: Session = Depends(get_db)):
    """Récupérer le nombre de tables (PUBLIC)"""
    config = db.query(ConfigDB).first()
    if not config:
        return {"nombre_tables": 10}
    return {"nombre_tables": config.nombre_tables}

@app.put("/admin/config/tables")
def update_table_config(data: ConfigUpdate, admin: dict = Depends(verify_admin_token), db: Session = Depends(get_db)):
    """Mettre à jour le nombre de tables (admin uniquement)"""
    if data.nombre_tables < 1 or data.nombre_tables > 100:
        raise HTTPException(status_code=400, detail="Le nombre de tables doit être entre 1 et 100")
    
    config = db.query(ConfigDB).first()
    if not config:
        config = ConfigDB(nombre_tables=data.nombre_tables)
        db.add(config)
    else:
        config.nombre_tables = data.nombre_tables
    
    db.commit()
    return {"message": f"Nombre de tables mis à jour: {data.nombre_tables}"}

# Événement de démarrage
@app.on_event("startup")
def startup_event():
    init_db()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8001))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
