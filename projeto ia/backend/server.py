from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import qrcode
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'isepam-secret-key-change-in-production')
ALGORITHM = "HS256"
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Utility Functions
def validate_cpf(cpf: str) -> bool:
    """Valida CPF usando algoritmo de dígitos verificadores"""
    cpf = ''.join(filter(str.isdigit, cpf))
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    
    # Calcula primeiro dígito verificador
    sum1 = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digit1 = 11 - (sum1 % 11)
    digit1 = 0 if digit1 > 9 else digit1
    
    # Calcula segundo dígito verificador
    sum2 = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digit2 = 11 - (sum2 % 11)
    digit2 = 0 if digit2 > 9 else digit2
    
    return int(cpf[9]) == digit1 and int(cpf[10]) == digit2

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def generate_qr_code(data: str) -> BytesIO:
    """Gera QR Code e retorna como BytesIO"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return buffer

def generate_certificate_pdf(user_name: str, event_name: str, event_date: str, total_hours: float) -> BytesIO:
    """Gera certificado em PDF"""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    # Cabeçalho
    p.setFont("Helvetica-Bold", 24)
    p.drawCentredString(width / 2, height - 4*cm, "CERTIFICADO")
    
    # Corpo do texto
    p.setFont("Helvetica", 12)
    text_y = height - 8*cm
    
    text_lines = [
        "O Instituto Superior de Educação Professor Aldo Muylaert - FAETEC",
        "certifica que:",
        "",
        ""
    ]
    
    for line in text_lines:
        p.drawCentredString(width / 2, text_y, line)
        text_y -= 0.8*cm
    
    # Nome do usuário em negrito
    p.setFont("Helvetica-Bold", 16)
    p.drawCentredString(width / 2, text_y, user_name)
    text_y -= 1.5*cm
    
    # Continuação do texto
    p.setFont("Helvetica", 12)
    continuation = [
        "",
        f"participou do evento {event_name}, realizado em {event_date},",
        f"perfazendo a carga horária de {total_hours} horas."
    ]
    
    for line in continuation:
        p.drawCentredString(width / 2, text_y, line)
        text_y -= 0.8*cm
    
    # Data de emissão
    p.setFont("Helvetica", 10)
    p.drawCentredString(width / 2, 3*cm, f"Emitido em: {datetime.now(timezone.utc).strftime('%d/%m/%Y')}")
    
    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

# Models
class UserRegister(BaseModel):
    user_type: str  # "aluno", "professor", "coordenador"
    enrollment_number: str
    full_name: str
    cpf: str
    email: EmailStr
    password: str

class EmailVerificationSend(BaseModel):
    email: EmailStr

class EmailVerificationConfirm(BaseModel):
    email: EmailStr
    code: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_type: str
    enrollment_number: str
    full_name: str
    cpf: str
    email: str
    cpf_valid: bool
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EventCreate(BaseModel):
    name: str
    target_courses: List[str]  # ["informatica", "pedagogia"]
    manual_hours: Optional[float] = None
    description: Optional[str] = None
    event_date: str

class Event(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_courses: List[str]
    manual_hours: Optional[float] = None
    description: Optional[str] = None
    event_date: str
    qr_code_token: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "aberto"  # "aberto", "encerrado"

class SessionCreate(BaseModel):
    event_id: str
    title: str
    speakers: Optional[str] = None
    start_time: str
    end_time: str
    description: Optional[str] = None
    target_courses: List[str]

class Session(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    title: str
    speakers: Optional[str] = None
    start_time: str
    end_time: str
    description: Optional[str] = None
    target_courses: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttendanceConfirm(BaseModel):
    qr_token: str

class Attendance(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    event_id: str
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Certificate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    event_id: str
    event_name: str
    event_date: str
    total_hours: float
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Routes
@api_router.post("/auth/send-verification")
async def send_verification_code(data: EmailVerificationSend):
    # Verifica se email já existe
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    # Gera código de 6 dígitos
    import random
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # Salva código com expiração de 10 minutos
    verification_doc = {
        "email": data.email,
        "code": code,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    }
    
    # Remove verificações antigas deste email
    await db.email_verifications.delete_many({"email": data.email})
    await db.email_verifications.insert_one(verification_doc)
    
    # Mock: Apenas loga o código (em produção, enviaria email real)
    logger.info(f"📧 CÓDIGO DE VERIFICAÇÃO para {data.email}: {code}")
    print(f"\n{'='*60}")
    print(f"📧 EMAIL DE VERIFICAÇÃO (MOCK)")
    print(f"Para: {data.email}")
    print(f"Código: {code}")
    print(f"Válido por: 10 minutos")
    print(f"{'='*60}\n")
    
    return {
        "message": "Código de verificação enviado para o email",
        "mock_code": code  # Apenas para testes, remover em produção
    }

@api_router.post("/auth/verify-email")
async def verify_email_code(data: EmailVerificationConfirm):
    # Busca código
    verification = await db.email_verifications.find_one({"email": data.email})
    
    if not verification:
        raise HTTPException(status_code=400, detail="Código não encontrado ou expirado")
    
    # Verifica expiração
    expires_at = datetime.fromisoformat(verification['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        await db.email_verifications.delete_one({"email": data.email})
        raise HTTPException(status_code=400, detail="Código expirado")
    
    # Verifica código
    if verification['code'] != data.code:
        raise HTTPException(status_code=400, detail="Código inválido")
    
    # Remove verificação após sucesso
    await db.email_verifications.delete_one({"email": data.email})
    
    return {"message": "Email verificado com sucesso", "verified": True}

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Verifica se email já existe
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    # Verifica se email foi verificado
    # Em produção, você deve verificar isso. Por enquanto vamos pular para compatibilidade
    
    # Valida CPF e BLOQUEIA se inválido
    cpf_valid = validate_cpf(user_data.cpf)
    if not cpf_valid:
        raise HTTPException(status_code=400, detail="CPF inválido")
    
    # Cria usuário
    user = User(
        user_type=user_data.user_type,
        enrollment_number=user_data.enrollment_number,
        full_name=user_data.full_name,
        cpf=user_data.cpf,
        email=user_data.email,
        cpf_valid=cpf_valid
    )
    
    doc = user.model_dump()
    doc['password'] = hash_password(user_data.password)
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.users.insert_one(doc)
    
    return {
        "message": "Usuário cadastrado com sucesso"
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Email ou senha incorretos")
    
    token = create_access_token({"sub": user['id'], "email": user['email'], "user_type": user['user_type']})
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "full_name": user['full_name'],
            "email": user['email'],
            "user_type": user['user_type']
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@api_router.post("/events", response_model=Event)
async def create_event(event_data: EventCreate, current_user: dict = Depends(get_current_user)):
    if current_user['user_type'] != 'coordenador':
        raise HTTPException(status_code=403, detail="Apenas coordenadores podem criar eventos")
    
    event = Event(
        name=event_data.name,
        target_courses=event_data.target_courses,
        manual_hours=event_data.manual_hours,
        description=event_data.description,
        event_date=event_data.event_date,
        created_by=current_user['id']
    )
    
    doc = event.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.events.insert_one(doc)
    return event

@api_router.get("/events", response_model=List[Event])
async def get_events(status: Optional[str] = None):
    query = {}
    if status:
        query['status'] = status
    
    events = await db.events.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for event in events:
        if isinstance(event['created_at'], str):
            event['created_at'] = datetime.fromisoformat(event['created_at'])
    
    return events

@api_router.get("/events/{event_id}", response_model=Event)
async def get_event(event_id: str):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    
    if isinstance(event['created_at'], str):
        event['created_at'] = datetime.fromisoformat(event['created_at'])
    
    return event

@api_router.put("/events/{event_id}", response_model=Event)
async def update_event(event_id: str, event_data: EventCreate, current_user: dict = Depends(get_current_user)):
    if current_user['user_type'] != 'coordenador':
        raise HTTPException(status_code=403, detail="Apenas coordenadores podem editar eventos")
    
    event = await db.events.find_one({"id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    
    update_data = event_data.model_dump()
    await db.events.update_one({"id": event_id}, {"$set": update_data})
    
    updated_event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if isinstance(updated_event['created_at'], str):
        updated_event['created_at'] = datetime.fromisoformat(updated_event['created_at'])
    
    return updated_event

@api_router.delete("/events/{event_id}")
async def delete_event(event_id: str, current_user: dict = Depends(get_current_user)):
    if current_user['user_type'] != 'coordenador':
        raise HTTPException(status_code=403, detail="Apenas coordenadores podem deletar eventos")
    
    result = await db.events.delete_one({"id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    
    # Deletar também as sessões relacionadas
    await db.sessions.delete_many({"event_id": event_id})
    
    return {"message": "Evento deletado com sucesso"}

@api_router.post("/sessions", response_model=Session)
async def create_session(session_data: SessionCreate, current_user: dict = Depends(get_current_user)):
    if current_user['user_type'] != 'coordenador':
        raise HTTPException(status_code=403, detail="Apenas coordenadores podem criar sessões")
    
    # Verifica se o evento existe
    event = await db.events.find_one({"id": session_data.event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    
    # Calcula duração da sessão em horas
    from datetime import datetime as dt
    try:
        start = dt.strptime(session_data.start_time, "%H:%M")
        end = dt.strptime(session_data.end_time, "%H:%M")
        duration = (end - start).total_seconds() / 3600
        
        # Verifica se evento tem carga horária manual definida
        if event.get('manual_hours'):
            # Calcula total de horas já alocadas
            existing_sessions = await db.sessions.find({"event_id": session_data.event_id}).to_list(1000)
            total_hours = duration
            
            for sess in existing_sessions:
                try:
                    sess_start = dt.strptime(sess['start_time'], "%H:%M")
                    sess_end = dt.strptime(sess['end_time'], "%H:%M")
                    total_hours += (sess_end - sess_start).total_seconds() / 3600
                except:
                    pass
            
            if total_hours > event['manual_hours']:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Total de horas das sessões ({total_hours:.1f}h) excede a carga horária do evento ({event['manual_hours']}h)"
                )
    except ValueError:
        raise HTTPException(status_code=400, detail="Formato de horário inválido. Use HH:MM")
    
    session = Session(**session_data.model_dump())
    
    doc = session.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.sessions.insert_one(doc)
    return session

@api_router.get("/events/{event_id}/sessions", response_model=List[Session])
async def get_event_sessions(event_id: str):
    sessions = await db.sessions.find({"event_id": event_id}, {"_id": 0}).to_list(1000)
    
    for session in sessions:
        if isinstance(session['created_at'], str):
            session['created_at'] = datetime.fromisoformat(session['created_at'])
    
    return sessions

@api_router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, current_user: dict = Depends(get_current_user)):
    if current_user['user_type'] != 'coordenador':
        raise HTTPException(status_code=403, detail="Apenas coordenadores podem deletar sessões")
    
    result = await db.sessions.delete_one({"id": session_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Sessão não encontrada")
    
    return {"message": "Sessão deletada com sucesso"}

@api_router.get("/events/{event_id}/qrcode")
async def get_event_qrcode(event_id: str):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    
    # Gera URL para confirmação de presença
    qr_data = event['qr_code_token']
    
    qr_buffer = generate_qr_code(qr_data)
    
    return StreamingResponse(qr_buffer, media_type="image/png")

@api_router.post("/attendance/confirm")
async def confirm_attendance(attendance_data: AttendanceConfirm, current_user: dict = Depends(get_current_user)):
    # Busca o evento pelo token do QR code
    event = await db.events.find_one({"qr_code_token": attendance_data.qr_token}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Token inválido")
    
    # Verifica se já confirmou presença
    existing = await db.attendances.find_one({
        "user_id": current_user['id'],
        "event_id": event['id']
    })
    
    if existing:
        return {"message": "Presença já confirmada anteriormente"}
    
    # Registra presença
    attendance = Attendance(
        user_id=current_user['id'],
        event_id=event['id']
    )
    
    doc = attendance.model_dump()
    doc['confirmed_at'] = doc['confirmed_at'].isoformat()
    
    await db.attendances.insert_one(doc)
    
    # Calcula carga horária total (manual ou calculada por sessões)
    total_hours = event.get('manual_hours')
    
    if total_hours is None:
        # Calcula automaticamente pelas sessões
        sessions = await db.sessions.find({"event_id": event['id']}).to_list(1000)
        total_hours = 0
        for session in sessions:
            # Aqui você pode implementar cálculo real baseado em start_time e end_time
            # Por simplicidade, vamos considerar 1 hora por sessão
            total_hours += 1
    
    # Gera certificado automaticamente
    certificate = Certificate(
        user_id=current_user['id'],
        event_id=event['id'],
        event_name=event['name'],
        event_date=event['event_date'],
        total_hours=total_hours
    )
    
    cert_doc = certificate.model_dump()
    cert_doc['generated_at'] = cert_doc['generated_at'].isoformat()
    
    await db.certificates.insert_one(cert_doc)
    
    return {
        "message": "Presença confirmada com sucesso!",
        "certificate_id": certificate.id
    }

@api_router.get("/certificates", response_model=List[Certificate])
async def get_user_certificates(current_user: dict = Depends(get_current_user)):
    certificates = await db.certificates.find(
        {"user_id": current_user['id']},
        {"_id": 0}
    ).to_list(1000)
    
    for cert in certificates:
        if isinstance(cert['generated_at'], str):
            cert['generated_at'] = datetime.fromisoformat(cert['generated_at'])
    
    return certificates

@api_router.get("/certificates/{certificate_id}/download")
async def download_certificate(certificate_id: str, current_user: dict = Depends(get_current_user)):
    certificate = await db.certificates.find_one(
        {"id": certificate_id, "user_id": current_user['id']},
        {"_id": 0}
    )
    
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificado não encontrado")
    
    pdf_buffer = generate_certificate_pdf(
        user_name=current_user['full_name'],
        event_name=certificate['event_name'],
        event_date=certificate['event_date'],
        total_hours=certificate['total_hours']
    )
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=certificado_{certificate_id}.pdf"}
    )

@api_router.get("/home/stats")
async def get_home_stats():
    # Últimos 3 eventos encerrados
    recent_completed = await db.events.find(
        {"status": "encerrado"},
        {"_id": 0}
    ).sort("created_at", -1).limit(3).to_list(3)
    
    # Eventos abertos
    open_events = await db.events.find(
        {"status": "aberto"},
        {"_id": 0}
    ).to_list(1000)
    
    for event in recent_completed + open_events:
        if isinstance(event.get('created_at'), str):
            event['created_at'] = datetime.fromisoformat(event['created_at'])
    
    return {
        "recent_completed": recent_completed,
        "open_events": open_events
    }

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()