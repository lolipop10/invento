from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
from datetime import datetime
import os
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlitecloud

# ==================== CONFIG ====================
app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'fallback_dev_key_only')
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================== SQLITECLOUD CONNECTION ====================
SQLITECLOUD_CONNECTION_STRING = "sqlitecloud://cpvyytm4hk.g2.sqlite.cloud:8860/inventory_12.db?apikey=9aagFJ25p8vWwwSkINdfvhGqkncYJmBCcz44ttVrZXg"

def get_db_connection():
    """Connexion à SQLiteCloud avec gestion d'erreur améliorée"""
    try:
        conn = sqlitecloud.connect(SQLITECLOUD_CONNECTION_STRING)
        conn.row_factory = sqlitecloud.Row
        return conn
    except Exception as e:
        print("Erreur connexion DB: {}".format(e))
        raise

# ==================== LOGIN ====================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Test de connexion au démarrage
try:
    test_conn = get_db_connection()
    print("SQLiteCloud Connection OK")
    test_conn.close()
except Exception as e:
    print("SQLiteCloud Connection Error: {}".format(e))

# ==================== USER CLASS ====================
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

    def is_admin(self):
        return self.role == 'admin'


@login_manager.user_loader
def load_user(user_id):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        res = c.execute("SELECT id, username, role FROM users WHERE id = ?", [user_id]).fetchone()
        if res:
            return User(res['id'], res['username'], res['role'])
        return None
    except Exception as e:
        print("Erreur load_user: {}".format(e))
        return None
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Accès refusé. Droits administrateur requis.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== UTILS ====================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def init_database():
    """Initialisation de la base de données sur SQLiteCloud"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Table des utilisateurs
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT,
                created_by INTEGER,
                is_active INTEGER DEFAULT 1
            )
        ''')

        # Table d'inventaire
        c.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                lot TEXT PRIMARY KEY,
                code_article TEXT,
                poids_physique REAL,
                remarque TEXT,
                date_scan TEXT,
                scanned_by INTEGER,
                FOREIGN KEY (scanned_by) REFERENCES users (id)
            )
        ''')

        # Table de configuration
        c.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # Table des messages
        c.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER,
                message TEXT NOT NULL,
                is_group_message INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Table de contrôle qualité
        c.execute('''
            CREATE TABLE IF NOT EXISTS quality_control (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lot TEXT NOT NULL UNIQUE,
                code_article TEXT,
                statut_qualite TEXT NOT NULL CHECK(statut_qualite IN ('CONFORME', 'NON_CONFORME', 'EN_ATTENTE')),
                non_conformite TEXT,
                decision_finale TEXT CHECK(decision_finale IN ('A_LIVRER', 'A_TRANSFORMER', 'A_RECYCLER', 'MAGASIN_NC', NULL)),
                controleur_id INTEGER,
                controleur_nom TEXT,
                date_controle TEXT DEFAULT (datetime('now')),
                date_modification TEXT,
                FOREIGN KEY (controleur_id) REFERENCES users(id)
            )
        ''')

        # Table d'historique de qualité
        c.execute('''
            CREATE TABLE IF NOT EXISTS quality_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lot TEXT NOT NULL,
                ancien_statut TEXT,
                nouveau_statut TEXT,
                ancienne_decision TEXT,
                nouvelle_decision TEXT,
                commentaire TEXT,
                modifie_par TEXT,
                date_modification TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table MB52 pour le stock système
        c.execute('''
            CREATE TABLE IF NOT EXISTS mb52_stock (
                lot TEXT PRIMARY KEY,
                code_article TEXT,
                poids_systeme REAL,
                date_import TEXT,
                imported_by INTEGER,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (imported_by) REFERENCES users (id)
            )
        ''')

        # Indices pour performances
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_lot ON quality_control(lot)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_statut ON quality_control(statut_qualite)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_decision ON quality_control(decision_finale)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_history_lot ON quality_history(lot)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_mb52_lot ON mb52_stock(lot)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_mb52_active ON mb52_stock(is_active)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_inventory_lot ON inventory(lot)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_chat_receiver ON chat_messages(receiver_id, is_read)")
        except Exception as e:
            print("Indices: {}".format(e))

        # Création d'un admin par défaut
        res = c.execute("SELECT COUNT(*) as cnt FROM users WHERE role='admin'").fetchone()
        cnt = res['cnt'] if res else 0
        if cnt == 0:
            password_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            c.execute('''
                INSERT INTO users (username, password_hash, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', password_hash, 'Administrateur', 'admin', datetime.now().isoformat()))

        conn.commit()
        print("Database initialized successfully on SQLiteCloud")

    except Exception as e:
        print("Erreur lors de l'initialisation de la base : {}".format(e))
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


def get_config(key, default=None):
    """Récupération configuration avec cache"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        res = c.execute("SELECT value FROM config WHERE key=?", [key]).fetchone()
        return res['value'] if res else default
    except Exception as e:
        print("Erreur get_config: {}".format(e))
        return default
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def set_config(key, value):
    """Sauvegarde la configuration dans la table config"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()
    except Exception as e:
        print(f"Erreur set_config: {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as close_err:
                print(f"Erreur lors de la fermeture de la connexion : {close_err}")



def get_mb52_poids(lot):
    """Récupère le poids système d'un lot depuis MB52"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        res = c.execute(
            "SELECT poids_systeme FROM mb52_stock WHERE lot = ? AND is_active = 1", 
            [lot]
        ).fetchone()
        return res['poids_systeme'] if res else None
    except Exception as e:
        print("Erreur get_mb52_poids: {}".format(e))
        return None
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def load_stock_data_from_db():
    """Charge les lots depuis la table MB52"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        rows = c.execute(
            "SELECT lot, poids_systeme FROM mb52_stock WHERE is_active = 1"
        ).fetchall()
        lots = [row['lot'] for row in rows]
        return lots, len(lots)
    except Exception as e:
        print("Erreur load_stock_data_from_db: {}".format(e))
        return [], 0
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def load_stock_data():
    """Load stock data from DB"""
    return load_stock_data_from_db()


def parse_barcode(barcode):
    """Simple barcode parsing"""
    barcode = (barcode or "").strip()
    import re
    if not re.match(r'^[A-Za-z0-9]+$', barcode):
        return "INVALID_CHARS", None
    if len(barcode) == 28:
        return barcode[8:18], barcode[18:]
    return None, None


def get_last_scan():
    """Récupère le dernier scan"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        res = c.execute("""
            SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
            FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
            ORDER BY i.date_scan DESC LIMIT 1
        """).fetchone()
        if res:
            return {
                'lot': res['lot'], 
                'code_article': res['code_article'], 
                'poids_physique': res['poids_physique'],
                'remarque': res['remarque'], 
                'date_scan': res['date_scan'], 
                'scanned_by': res['username']
            }
        return None
    except Exception as e:
        print("Erreur get_last_scan: {}".format(e))
        return None
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def get_inventory_data():
    """Récupère les données d'inventaire avec vérification"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        scanned = c.execute("""
            SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
            FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
            ORDER BY i.date_scan DESC
        """).fetchall()
        
        lots_stock, _ = load_stock_data()
        result = []
        for row in scanned:
            lot = row['lot']
            result.append((
                lot,
                row['code_article'],
                row['poids_physique'],
                row['remarque'],
                row['date_scan'],
                row['username'],
                ('OK' if lot in lots_stock else 'NOK')
            ))
        return result
    except Exception as e:
        print("Erreur get_inventory_data: {}".format(e))
        return []
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def get_dashboard_stats():
    """Calcule les statistiques du dashboard"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        nb_row = c.execute("SELECT COUNT(DISTINCT lot) as c FROM inventory").fetchone()
        nb = nb_row['c'] if nb_row else 0
        
        first_row = c.execute("SELECT MIN(date_scan) as f FROM inventory").fetchone()
        first = first_row['f'] if first_row else None
        
        last_row = c.execute("SELECT MAX(date_scan) as l FROM inventory").fetchone()
        last = last_row['l'] if last_row else None
        
        cadence = 0
        if first and last:
            try:
                first_dt = datetime.fromisoformat(first)
                last_dt = datetime.fromisoformat(last)
                elapsed = (last_dt - first_dt).total_seconds() / 3600.0
                cadence = nb / elapsed if elapsed > 0 else 0
            except Exception:
                cadence = 0
        
        _, cible = load_stock_data()
        
        return {
            'nb_bobines_scannees': nb, 
            'cible_lot': cible, 
            'cadence': round(cadence, 2),
            'first_scan_time': first, 
            'last_scan_time': last
        }
    except Exception as e:
        print("Erreur get_dashboard_stats: {}".format(e))
        return {
            'nb_bobines_scannees': 0,
            'cible_lot': 0,
            'cadence': 0,
            'first_scan_time': None,
            'last_scan_time': None
        }
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def get_unread_messages_count():
    """Compte les messages non lus"""
    if not current_user or not current_user.is_authenticated:
        return 0
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        direct_row = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
            [current_user.id]
        ).fetchone()
        direct = direct_row['cnt'] if direct_row else 0
        
        group_row = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
            [current_user.id]
        ).fetchone()
        group = group_row['cnt'] if group_row else 0
        
        return int(direct) + int(group)
    except Exception as e:
        print("Erreur get_unread_messages_count: {}".format(e))
        return 0
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.context_processor
def inject_company_info():
    return {
        'company_logo': get_config('company_logo', None),
        'company_name': get_config('company_name', 'Inventory Management')
    }


def verify_export_token(token_key='export_token', max_age_seconds=300):
    """Vérifie la validité d'un token d'export"""
    export_token = session.get(token_key)
    if not export_token:
        return False, "Token manquant"
    
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > max_age_seconds:
            session.pop(token_key, None)
            return False, "Token expiré"
        return True, "OK"
    except Exception:
        session.pop(token_key, None)
        return False, "Token invalide"


# ==================== ROUTES AUTH ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            res = c.execute(
                "SELECT id, username, password_hash, role, is_active FROM users WHERE username=?",
                [username]
            ).fetchone()
            
            if res and res['is_active'] and check_password_hash(res['password_hash'], password):
                login_user(User(res['id'], res['username'], res['role']))
                flash('Connexion réussie', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
        except Exception as e:
            print("Erreur login: {}".format(e))
            flash('Erreur de connexion', 'error')
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnecté', 'info')
    return redirect(url_for('login'))


# ==================== ROUTES MAIN ====================

@app.route('/')
@login_required
def dashboard():
    stats = get_dashboard_stats()
    inventory_data = get_inventory_data()
    last_scan = get_last_scan()
    unread_count = get_unread_messages_count()
    
    return render_template(
        'dashboard.html',
        stats=stats,
        inventory_data=inventory_data,
        last_scan=last_scan,
        unread_count=unread_count
    )


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    last_scan = get_last_scan()
    
    if request.method == 'POST':
        barcode = request.form.get('barcode', '').strip()
        poids = request.form.get('poids', type=float)
        remarques = request.form.getlist('remarque')
        
        if barcode:
            code_article, lot = parse_barcode(barcode)
            
            if code_article == "INVALID_CHARS":
                flash('Caractères invalides', 'error')
                return render_template('scan.html', last_scan=last_scan)
            
            if code_article and lot:
                # Récupérer le poids système si non fourni
                if poids is None or poids == 0:
                    poids_systeme = get_mb52_poids(lot)
                    if poids_systeme:
                        poids = poids_systeme 
                        remarques.append('Poids auto-rempli depuis MB52')
                
                conn = None
                try:
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO inventory (lot, code_article, poids_physique, remarque, date_scan, scanned_by) VALUES (?, ?, ?, ?, ?, ?)",
                        [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id]
                    )
                    conn.commit()
                    flash('Lot {} ajouté'.format(lot), 'success')
                    return redirect(url_for('scan'))
                except Exception as e:
                    if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                        flash('Lot déjà existant', 'error')
                    else:
                        flash('Erreur: {}'.format(str(e)), 'error')
                finally:
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
            else:
                flash('Code-barres invalide', 'error')
    
    return render_template('scan.html', last_scan=last_scan)


@app.route('/manual', methods=['GET', 'POST'])
@login_required
def manual_entry():
    if request.method == 'POST':
        lot = request.form.get('lot', '').strip()
        code_article = request.form.get('code_article', '').strip()
        poids = request.form.get('poids', 0, type=float)
        remarques = request.form.getlist('remarque')
        
        if lot and code_article:
            conn = None
            try:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute(
                    "INSERT INTO inventory (lot, code_article, poids_physique, remarque, date_scan, scanned_by) VALUES (?, ?, ?, ?, ?, ?)",
                    [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id]
                )
                conn.commit()
                flash('Lot {} ajouté'.format(lot), 'success')
                return redirect(url_for('manual_entry'))
            except Exception as e:
                if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                    flash('Lot déjà existant', 'error')
                else:
                    flash('Erreur: {}'.format(str(e)), 'error')
            finally:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
        else:
            flash('Veuillez entrer lot et code article', 'error')
    
    return render_template('manual.html')


@app.route('/search')
@login_required
def search():
    search_lot = request.args.get('lot', '').strip()
    inventory_data = get_inventory_data()
    
    if search_lot:
        filtered = [row for row in inventory_data if search_lot in row[0]]
    else:
        filtered = inventory_data
    
    return render_template('search.html', inventory_data=filtered, search_lot=search_lot)


# ==================== ROUTES EXPORT - APPROCHE IDENTIQUE ====================

@app.route('/verify-export-password', methods=['POST'])
@login_required
@admin_required
def verify_export_password():
    """Vérifie le mot de passe d'export"""
    try:
        data = request.get_json(force=True)
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'message': 'Mot de passe requis'}), 400
        
        export_password = get_config('export_password', None)
        
        if not export_password:
            return jsonify({'success': False, 'message': 'Aucun mot de passe configuré'}), 400
        
        if check_password_hash(export_password, password):
            session['export_token'] = datetime.now().isoformat()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401
            
    except Exception as e:
        print("Erreur verify_export_password: {}".format(e))
        return jsonify({'success': False, 'message': 'Erreur serveur'}), 500


@app.route('/export', methods=['POST'])
@login_required
@admin_required
def export_data():
    """Export des données d'inventaire"""
    export_token = session.get('export_token')
    if not export_token:
        flash('Veuillez d\'abord vous authentifier pour l\'export', 'error')
        return redirect(url_for('search'))
    
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > 300:
            session.pop('export_token', None)
            flash('Session d\'export expirée. Veuillez vous authentifier à nouveau', 'error')
            return redirect(url_for('search'))
    except Exception:
        session.pop('export_token', None)
        flash('Token d\'export invalide', 'error')
        return redirect(url_for('search'))
    
    session.pop('export_token', None)
    
    data = get_inventory_data()
    df = pd.DataFrame(data, columns=["Lot","Code Article","Poids Physique","Remarque","Date Scan","Scanné par","Vérification"])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='inventory')
    output.seek(0)
    filename = "inventory_{}.xlsx".format(datetime.now().strftime('%Y%m%d_%H%M%S'))
    return send_file(output, as_attachment=True, download_name=filename,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ==================== EXPORT QUALITÉ - MÊME APPROCHE ====================

@app.route('/verify-quality-export-password', methods=['POST'])
@login_required
def verify_quality_export_password():
    """Vérifie le mot de passe d'export qualité"""
    try:
        data = request.get_json(force=True)
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'message': 'Mot de passe requis'}), 400
        
        export_password = get_config('export_password', None)
        
        if not export_password:
            return jsonify({'success': False, 'message': 'Aucun mot de passe configuré'}), 400
        
        if check_password_hash(export_password, password):
            session['export_token_quality'] = datetime.now().isoformat()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401
            
    except Exception as e:
        print("Erreur verify_quality_export_password: {}".format(e))
        return jsonify({'success': False, 'message': 'Erreur serveur'}), 500


@app.route('/quality-export')
@login_required
def quality_export():
    """Export du contrôle qualité - APPROCHE IDENTIQUE À export_data"""
    export_token = session.get('export_token_quality')
    if not export_token:
        flash('Veuillez d\'abord vous authentifier pour l\'export', 'error')
        return redirect(url_for('quality_control'))
    
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > 300:
            session.pop('export_token_quality', None)
            flash('Session d\'export expirée. Veuillez vous authentifier à nouveau', 'error')
            return redirect(url_for('quality_control'))
    except Exception:
        session.pop('export_token_quality', None)
        flash('Token d\'export invalide', 'error')
        return redirect(url_for('quality_control'))
    
    session.pop('export_token_quality', None)
    
    conn = get_db_connection()
    query = """
        SELECT 
            i.lot,
            i.code_article,
            i.poids_physique,
            COALESCE(qc.statut_qualite, 'EN_ATTENTE') as statut_qualite,
            qc.non_conformite,
            qc.decision_finale,
            qc.controleur_nom,
            qc.date_controle,
            i.date_scan
        FROM inventory i
        LEFT JOIN quality_control qc ON i.lot = qc.lot
        ORDER BY i.date_scan DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    df.columns = ['Lot', 'Code Article', 'Poids Physique', 'Statut Qualité', 
                  'Non Conformité', 'Décision Finale', 'Contrôleur', 'Date Contrôle', 'Date Scan']
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Contrôle Qualité', index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='controle_qualite_{}.xlsx'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))
    )


# ==================== EXPORT RAPPROCHEMENT - MÊME APPROCHE ====================

@app.route('/verify-reconciliation-export-password', methods=['POST'])
@login_required
@admin_required
def verify_reconciliation_export_password():
    """Vérifie le mot de passe d'export pour le rapprochement"""
    try:
        data = request.get_json(force=True)
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'message': 'Mot de passe requis'}), 400
        
        export_password = get_config('export_password', None)
        
        if not export_password:
            return jsonify({'success': False, 'message': 'Aucun mot de passe configuré'}), 400
        
        if check_password_hash(export_password, password):
            session['export_token_reconciliation'] = datetime.now().isoformat()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401
            
    except Exception as e:
        print("Erreur verify_reconciliation_export_password: {}".format(e))
        return jsonify({'success': False, 'message': 'Erreur serveur'}), 500


@app.route('/reconciliation/export')
@login_required
@admin_required
def export_reconciliation():
    """Export du rapprochement vers Excel - APPROCHE IDENTIQUE"""
    export_token = session.get('export_token_reconciliation')
    if not export_token:
        flash('Veuillez d\'abord vous authentifier pour l\'export', 'error')
        return redirect(url_for('reconciliation'))
    
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > 300:
            session.pop('export_token_reconciliation', None)
            flash('Session d\'export expirée. Veuillez vous authentifier à nouveau', 'error')
            return redirect(url_for('reconciliation'))
    except Exception:
        session.pop('export_token_reconciliation', None)
        flash('Token d\'export invalide', 'error')
        return redirect(url_for('reconciliation'))
    
    session.pop('export_token_reconciliation', None)
    
    conn = get_db_connection()
    
    query = """
        SELECT 
            i.lot as lot,
            i.code_article as code_physique,
            m.code_article as code_systeme,
            i.poids_physique,
            m.poids_systeme,
            CASE
                WHEN i.poids_physique IS NOT NULL AND m.poids_systeme IS NOT NULL
                THEN (i.poids_physique - m.poids_systeme)
                ELSE NULL
            END as ecart_poids,
            CASE 
                WHEN i.poids_physique IS NOT NULL AND m.poids_systeme IS NOT NULL AND m.poids_systeme != 0
                THEN ((i.poids_physique - m.poids_systeme) / m.poids_systeme * 100)
                ELSE NULL
            END as ecart_pourcent,
            i.date_scan,
            m.date_import,
            u.username as scanned_by,
            CASE 
                WHEN m.lot IS NULL THEN 'Physique seul'
                WHEN ABS(COALESCE(i.poids_physique, 0) - COALESCE(m.poids_systeme, 0)) <= 0.1 THEN 'Conforme'
                ELSE 'Écart'
            END as statut
        FROM inventory i
        LEFT JOIN mb52_stock m ON i.lot = m.lot AND m.is_active = 1
        LEFT JOIN users u ON i.scanned_by = u.id
        
        UNION ALL
        
        SELECT 
            m.lot as lot,
            NULL as code_physique,
            m.code_article as code_systeme,
            NULL as poids_physique,
            m.poids_systeme,
            NULL as ecart_poids,
            NULL as ecart_pourcent,
            NULL as date_scan,
            m.date_import,
            NULL as scanned_by,
            'Système seul' as statut
        FROM mb52_stock m
        WHERE m.is_active = 1 AND m.lot NOT IN (SELECT lot FROM inventory)
        
    """
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    df.columns = ['Lot', 'Code Physique', 'Code Système', 'Poids Physique', 'Poids Système', 
                  'Écart Poids', 'Écart %', 'Date Scan', 'Date Import', 'Scanné par', 'Statut']
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Rapprochement', index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='rapprochement_{}.xlsx'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))
    )


# ==================== ROUTES MB52 ====================

@app.route('/mb52/import', methods=['GET', 'POST'])
@login_required
@admin_required
def import_mb52():
    """Import du fichier MB52 vers la base de données"""
    if request.method == 'POST':
        file = request.files.get('mb52_file')
        
        if not file or not file.filename.endswith(('.xlsx', '.xls')):
            flash('Fichier Excel invalide', 'error')
            return redirect(url_for('import_mb52'))
        
        conn = None
        try:
            df = pd.read_excel(file)
            
            if 'Lot' not in df.columns or 'Poids' not in df.columns:
                flash('Le fichier doit contenir les colonnes "Lot" et "Poids"', 'error')
                return redirect(url_for('import_mb52'))
            
            has_code_article = 'Code Article' in df.columns or 'code_article' in df.columns
            
            df['Lot'] = df['Lot'].astype(str).apply(lambda x: x.zfill(10))
            df['Poids'] = pd.to_numeric(df['Poids'], errors='coerce')
            df = df.dropna(subset=['Poids'])
            
            if len(df) == 0:
                flash('Aucune donnée valide trouvée dans le fichier', 'error')
                return redirect(url_for('import_mb52'))
            
            conn = get_db_connection()
            c = conn.cursor()
            
            action = request.form.get('import_action', 'replace')
            
            if action == 'replace':
                c.execute("UPDATE mb52_stock SET is_active = 0")
            
            imported = 0
            errors = 0
            
            for _, row in df.iterrows():
                lot = row['Lot']
                poids = row['Poids']
                code_article = row.get('Code Article', row.get('code_article', None))
                
                try:
                    c.execute("""
                        INSERT INTO mb52_stock 
                        (lot, code_article, poids_systeme, date_import, imported_by, is_active)
                        VALUES (?, ?, ?, ?, ?, 1)
                        ON CONFLICT(lot) DO UPDATE SET
                            poids_systeme = excluded.poids_systeme,
                            code_article = excluded.code_article,
                            date_import = excluded.date_import,
                            imported_by = excluded.imported_by,
                            is_active = 1
                    """, [lot, code_article, poids, datetime.now().isoformat(), current_user.id])
                    imported += 1
                except Exception as e:
                    errors += 1
                    print("Erreur import lot {}: {}".format(lot, e))
            
            conn.commit()
            flash('Import réussi: {} lots importés, {} erreurs'.format(imported, errors), 'success')
            return redirect(url_for('mb52_management'))
            
        except Exception as e:
            print("Erreur import_mb52: {}".format(e))
            flash('Erreur lors de l\'import: {}'.format(str(e)), 'error')
            return redirect(url_for('import_mb52'))
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        stats = c.execute("""
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as actifs,
                MAX(date_import) as derniere_import
            FROM mb52_stock
        """).fetchone()
        return render_template('mb52_import.html', stats=stats)
    except Exception as e:
        print("Erreur affichage import_mb52: {}".format(e))
        return render_template('mb52_import.html', stats=None)
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/mb52/management')
@login_required
@admin_required
def mb52_management():
    """Page de gestion du stock MB52"""
    search = request.args.get('search', '')
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        stats = c.execute("""
            SELECT 
                COUNT(*) as total_lots,
                SUM(poids_systeme) as poids_total,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as lots_actifs,
                MAX(date_import) as derniere_import
            FROM mb52_stock
        """).fetchone()
        
        query = "SELECT lot, code_article, poids_systeme, date_import, is_active FROM mb52_stock"
        params = []
        
        if search:
            query += " WHERE lot LIKE ? OR code_article LIKE ?"
            params = ['%{}%'.format(search), '%{}%'.format(search)]
        
        query += " ORDER BY date_import DESC LIMIT 1000"
        
        lots = c.execute(query, params).fetchall()
        
        return render_template('mb52_management.html', stats=stats, lots=lots, search=search)
        
    except Exception as e:
        print("Erreur mb52_management: {}".format(e))
        flash('Erreur lors du chargement des données', 'error')
        return render_template('mb52_management.html', stats=None, lots=[], search=search)
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


# ==================== ROUTES RAPPROCHEMENT ====================

@app.route('/reconciliation')
@login_required
@admin_required
def reconciliation():
    """Page de rapprochement Physique vs SAP"""
    filter_status = request.args.get('status', 'all')
    search = request.args.get('search', '')
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        base_query = """
            WITH reconciliation_data AS (
                SELECT 
                    i.lot as lot,
                    i.code_article as code_physique,
                    m.code_article as code_systeme,
                    i.poids_physique,
                    m.poids_systeme,
                    i.date_scan,
                    m.date_import,
                    u.username as scanned_by,
                    CASE 
                        WHEN m.lot IS NULL THEN 'PHYSIQUE_SEUL'
                        ELSE 'PRESENT'
                    END as statut_presence,
                    CASE 
                        WHEN i.poids_physique IS NOT NULL AND m.poids_systeme IS NOT NULL 
                        THEN (i.poids_physique - m.poids_systeme)
                        ELSE NULL
                    END as ecart_poids
                FROM inventory i
                LEFT JOIN mb52_stock m ON i.lot = m.lot AND m.is_active = 1
                LEFT JOIN users u ON i.scanned_by = u.id
                
                UNION ALL
                
                SELECT 
                    m.lot as lot,
                    NULL as code_physique,
                    m.code_article as code_systeme,
                    NULL as poids_physique,
                    m.poids_systeme,
                    NULL as date_scan,
                    m.date_import,
                    NULL as scanned_by,
                    'SYSTEME_SEUL' as statut_presence,
                    NULL as ecart_poids
                FROM mb52_stock m
                WHERE m.is_active = 1 AND m.lot NOT IN (SELECT lot FROM inventory)
            )
            SELECT * FROM reconciliation_data
        """
        
        conditions = []
        params = []
        
        if filter_status == 'conforme':
            conditions.append("(ABS(COALESCE(ecart_poids, 999999)) <= 0.1 AND statut_presence = 'PRESENT')")
        elif filter_status == 'ecart':
            conditions.append("(ABS(COALESCE(ecart_poids, 0)) > 0.1 AND statut_presence = 'PRESENT')")
        elif filter_status == 'physique_seul':
            conditions.append("statut_presence = 'PHYSIQUE_SEUL'")
        elif filter_status == 'systeme_seul':
            conditions.append("statut_presence = 'SYSTEME_SEUL'")
        
        if search:
            conditions.append("lot LIKE ?")
            params.append('%{}%'.format(search))
        
        if conditions:
            query = "{} WHERE {}".format(base_query, " AND ".join(conditions))
        else:
            query = base_query
        
        query += " ORDER BY ABS(COALESCE(ecart_poids, 999999)) DESC LIMIT 1000"
        
        reconciliation_data = c.execute(query, params).fetchall()
        
        stats_query = """
            SELECT 
                (SELECT COUNT(DISTINCT lot) FROM inventory) as lots_physiques,
                (SELECT COUNT(DISTINCT lot) FROM mb52_stock WHERE is_active = 1) as lots_systeme,
                (SELECT COUNT(DISTINCT i.lot) FROM inventory i 
                 INNER JOIN mb52_stock m ON i.lot = m.lot AND m.is_active = 1) as lots_communs,
                (SELECT COUNT(DISTINCT lot) FROM inventory 
                 WHERE lot NOT IN (SELECT lot FROM mb52_stock WHERE is_active = 1)) as physique_seul,
                (SELECT COUNT(DISTINCT lot) FROM mb52_stock 
                 WHERE is_active = 1 AND lot NOT IN (SELECT lot FROM inventory)) as systeme_seul,
                (SELECT COUNT(*) FROM inventory i 
                 INNER JOIN mb52_stock m ON i.lot = m.lot AND m.is_active = 1
                 WHERE ABS(i.poids_physique - m.poids_systeme) <= 0.1) as conformes,
                (SELECT COUNT(*) FROM inventory i 
                 INNER JOIN mb52_stock m ON i.lot = m.lot AND m.is_active = 1
                 WHERE ABS(i.poids_physique - m.poids_systeme) > 0.1) as ecarts
        """
        
        stats = c.execute(stats_query).fetchone()
        
        return render_template(
            'reconciliation.html', 
            data=reconciliation_data, 
            stats=stats,
            filter_status=filter_status,
            search=search
        )
        
    except Exception as e:
        print("Erreur reconciliation: {}".format(e))
        flash('Erreur lors du chargement du rapprochement', 'error')
        return render_template('reconciliation.html', data=[], stats=None, filter_status=filter_status, search=search)
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


# ==================== ROUTES QUALITÉ ====================

@app.route('/quality-control')
@login_required
def quality_control():
    """Page d'accueil du contrôle qualité"""
    conn = None
    
    default_stats = {
        'conformes': 0,
        'non_conformes': 0,
        'en_attente': 0,
        'total': 0,
        'taux_conformite': 0
    }
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        filter_statut = request.args.get('statut', '')
        filter_decision = request.args.get('decision', '')
        search_term = request.args.get('search', '')
        
        query = """
            SELECT 
                i.lot,
                i.code_article,
                i.poids_physique,
                i.date_scan,
                COALESCE(qc.statut_qualite, 'EN_ATTENTE') as statut_qualite,
                qc.decision_finale,
                qc.non_conformite,
                qc.controleur_nom,
                qc.date_controle
            FROM inventory i
            LEFT JOIN quality_control qc ON i.lot = qc.lot
            WHERE 1=1
        """
        params = []
        
        if filter_statut:
            query += " AND COALESCE(qc.statut_qualite, 'EN_ATTENTE') = ?"
            params.append(filter_statut)
        
        if filter_decision:
            query += " AND qc.decision_finale = ?"
            params.append(filter_decision)
        
        if search_term:
            query += " AND i.lot LIKE ?"
            params.append('%{}%'.format(search_term))
        
        query += " ORDER BY i.date_scan DESC LIMIT 1000"
        
        lots_data = c.execute(query, params).fetchall()
        
        lots = []
        for row in lots_data:
            lots.append({
                'lot': row['lot'],
                'code_article': row['code_article'],
                'poids_physique': row['poids_physique'],
                'date_scan': row['date_scan'],
                'statut_qualite': row['statut_qualite'],
                'decision_finale': row['decision_finale'],
                'non_conformite': row['non_conformite'],
                'controleur_nom': row['controleur_nom'],
                'date_controle': row['date_controle']
            })
        
        stats_row = c.execute("""
            SELECT 
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'CONFORME' THEN 1 ELSE 0 END) as conformes,
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'NON_CONFORME' THEN 1 ELSE 0 END) as non_conformes,
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'EN_ATTENTE' THEN 1 ELSE 0 END) as en_attente,
                COUNT(*) as total
            FROM inventory i
            LEFT JOIN quality_control qc ON i.lot = qc.lot
        """).fetchone()
        
        if stats_row:
            stats = {
                'conformes': stats_row['conformes'] or 0,
                'non_conformes': stats_row['non_conformes'] or 0,
                'en_attente': stats_row['en_attente'] or 0,
                'total': stats_row['total'] or 0
            }
            stats['taux_conformite'] = (stats['conformes'] / stats['total'] * 100) if stats['total'] > 0 else 0
        else:
            stats = default_stats
        
        return render_template('quality_control.html', 
                               lots=lots, 
                               stats=stats,
                               filter_statut=filter_statut,
                               filter_decision=filter_decision,
                               search_term=search_term)
        
    except Exception as e:
        print("Erreur quality_control: {}".format(e))
        import traceback
        traceback.print_exc()
        flash('Erreur lors du chargement du contrôle qualité', 'error')
        return render_template('quality_control.html', 
                             lots=[], 
                             stats=default_stats,
                             filter_statut='',
                             filter_decision='',
                             search_term='')
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/save-quality-control', methods=['POST'])
@login_required
def save_quality_control():
    """Sauvegarde du contrôle qualité"""
    lot = request.form.get('lot')
    statut_qualite = request.form.get('statut_qualite')
    non_conformite = request.form.get('non_conformite', '').strip()
    decision_finale = request.form.get('decision_finale', '').strip()
    
    if not lot or not statut_qualite:
        flash('Données invalides.', 'error')
        return redirect(url_for('quality_control'))
    
    if statut_qualite == 'NON_CONFORME' and not non_conformite:
        flash('La description de la non-conformité est obligatoire.', 'error')
        return redirect(url_for('quality_control'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        article_row = c.execute("SELECT code_article FROM inventory WHERE lot = ?", (lot,)).fetchone()
        code_article = article_row['code_article'] if article_row else None
        
        existing = c.execute("SELECT statut_qualite, decision_finale FROM quality_control WHERE lot = ?", (lot,)).fetchone()
        
        now_iso = datetime.now().isoformat()
        
        if existing:
            c.execute("""
                INSERT INTO quality_history (lot, ancien_statut, nouveau_statut, ancienne_decision, nouvelle_decision, commentaire, modifie_par)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (lot, existing['statut_qualite'], statut_qualite, existing['decision_finale'], decision_finale or None, non_conformite, current_user.username))
            
            c.execute("""
                UPDATE quality_control 
                SET statut_qualite = ?,
                    non_conformite = ?,
                    decision_finale = ?,
                    controleur_id = ?,
                    controleur_nom = ?,
                    date_modification = ?
                WHERE lot = ?
            """, (statut_qualite, non_conformite or None, decision_finale or None, 
                  current_user.id, current_user.username, now_iso, lot))
            
            flash('Contrôle qualité mis à jour pour le lot {}.'.format(lot), 'success')
        else:
            c.execute("""
                INSERT INTO quality_control (lot, code_article, statut_qualite, non_conformite, decision_finale, controleur_id, controleur_nom, date_controle)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (lot, code_article, statut_qualite, non_conformite or None, decision_finale or None, 
                  current_user.id, current_user.username, now_iso))
            
            c.execute("""
                INSERT INTO quality_history (lot, ancien_statut, nouveau_statut, commentaire, modifie_par)
                VALUES (?, ?, ?, ?, ?)
            """, (lot, 'EN_ATTENTE', statut_qualite, non_conformite, current_user.username))
            
            flash('Contrôle qualité enregistré pour le lot {}.'.format(lot), 'success')
        
        conn.commit()
        return redirect(url_for('quality_control'))
        
    except Exception as e:
        print("Erreur save_quality_control: {}".format(e))
        flash('Erreur lors de la sauvegarde: {}'.format(str(e)), 'error')
        return redirect(url_for('quality_control'))
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/quality-batch-update', methods=['POST'])
@login_required
def quality_batch_update():
    """Mise à jour par lot"""
    lots = request.form.getlist('lots')
    statut = request.form.get('statut')
    
    if not lots or not statut:
        flash('Données invalides.', 'error')
        return redirect(url_for('quality_control'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        updated = 0
        now_iso = datetime.now().isoformat()
        
        for lot in lots:
            exists = c.execute("SELECT id FROM quality_control WHERE lot = ?", (lot,)).fetchone()
            
            article_row = c.execute("SELECT code_article FROM inventory WHERE lot = ?", (lot,)).fetchone()
            code_article = article_row['code_article'] if article_row else None
            
            if exists:
                c.execute("""
                    UPDATE quality_control 
                    SET statut_qualite = ?,
                        controleur_id = ?,
                        controleur_nom = ?,
                        date_modification = ?
                    WHERE lot = ?
                """, (statut, current_user.id, current_user.username, now_iso, lot))
            else:
                c.execute("""
                    INSERT INTO quality_control (lot, code_article, statut_qualite, controleur_id, controleur_nom, date_controle)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (lot, code_article, statut, current_user.id, current_user.username, now_iso))
            
            c.execute("""
                INSERT INTO quality_history (lot, nouveau_statut, modifie_par, date_modification)
                VALUES (?, ?, ?, ?)
            """, (lot, statut, current_user.username, now_iso))
            
            updated += 1
        
        conn.commit()
        flash('{} lot(s) mis à jour avec le statut {}.'.format(updated, statut), 'success')
        return redirect(url_for('quality_control'))
        
    except Exception as e:
        print("Erreur quality_batch_update: {}".format(e))
        flash('Erreur lors de la mise à jour: {}'.format(str(e)), 'error')
        return redirect(url_for('quality_control'))
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/api/quality-stats')
@login_required
def quality_stats_api():
    """API pour les statistiques qualité"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        row = c.execute("""
            SELECT 
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'CONFORME' THEN 1 ELSE 0 END) as conformes,
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'NON_CONFORME' THEN 1 ELSE 0 END) as non_conformes,
                SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'EN_ATTENTE' THEN 1 ELSE 0 END) as en_attente,
                COUNT(*) as total
            FROM inventory i
            LEFT JOIN quality_control qc ON i.lot = qc.lot
        """).fetchone()
        
        conformes = row['conformes'] or 0
        non_conformes = row['non_conformes'] or 0
        en_attente = row['en_attente'] or 0
        total = row['total'] or 0
        
        taux_conformite = (conformes / total * 100) if total > 0 else 0
        
        return jsonify({
            'conformes': conformes,
            'non_conformes': non_conformes,
            'en_attente': en_attente,
            'taux_conformite': round(taux_conformite, 1)
        })
        
    except Exception as e:
        print("Erreur quality_stats_api: {}".format(e))
        return jsonify({
            'conformes': 0,
            'non_conformes': 0,
            'en_attente': 0,
            'taux_conformite': 0
        })
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


# ==================== ROUTES UTILISATEURS ====================

@app.route('/users')
@login_required
@admin_required
def users():
    """Liste des utilisateurs"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        users_list = c.execute(
            "SELECT id, username, full_name, role, created_at, is_active FROM users ORDER BY created_at DESC"
        ).fetchall()
        return render_template('users.html', users=users_list)
    except Exception as e:
        print("Erreur users: {}".format(e))
        flash('Erreur lors du chargement des utilisateurs', 'error')
        return render_template('users.html', users=[])
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Création d'un utilisateur"""
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        fn = request.form.get('full_name', '').strip()
        r = request.form.get('role', 'user')
        
        if not u or not p:
            flash('Nom d\'utilisateur et mot de passe requis', 'error')
            return render_template('create_user.html')
        
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password_hash, full_name, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                [u, generate_password_hash(p), fn, r, datetime.now().isoformat(), current_user.id]
            )
            conn.commit()
            flash('Utilisateur créé', 'success')
            return redirect(url_for('users'))
        except Exception as e:
            if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                flash('Nom d\'utilisateur déjà utilisé', 'error')
            else:
                flash('Erreur: {}'.format(str(e)), 'error')
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    return render_template('create_user.html')


@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    """Active/Désactive un utilisateur"""
    if user_id == current_user.id:
        flash('Impossible de désactiver votre compte', 'error')
        return redirect(url_for('users'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 1 - is_active WHERE id = ?", [user_id])
        conn.commit()
        flash('Statut mis à jour', 'success')
    except Exception as e:
        print("Erreur toggle_user: {}".format(e))
        flash('Erreur lors de la mise à jour', 'error')
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Supprime un utilisateur"""
    if user_id == current_user.id:
        flash('Impossible de supprimer votre compte', 'error')
        return redirect(url_for('users'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", [user_id])
        conn.commit()
        flash('Utilisateur supprimé', 'success')
    except Exception as e:
        print("Erreur delete_user: {}".format(e))
        flash('Erreur lors de la suppression', 'error')
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    return redirect(url_for('users'))


# ==================== ROUTES CHAT ====================

@app.route('/chat')
@login_required
def chat():
    """Page de chat"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        users_list = c.execute(
            "SELECT id, username, full_name FROM users WHERE id != ? AND is_active = 1 ORDER BY username",
            [current_user.id]
        ).fetchall()
        return render_template('chat.html', users=users_list)
    except Exception as e:
        print("Erreur chat: {}".format(e))
        return render_template('chat.html', users=[])
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/chat/messages')
@login_required
def chat_messages():
    """Récupère les messages de chat"""
    chat_type = request.args.get('type', 'direct')
    other_id = request.args.get('user_id', type=int)

    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        if chat_type == 'group':
            messages = c.execute("""
                SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                FROM chat_messages cm
                JOIN users u ON cm.sender_id = u.id
                WHERE cm.is_group_message = 1
                ORDER BY cm.created_at DESC
                LIMIT 100
            """).fetchall()

            c.execute(
                "UPDATE chat_messages SET is_read = 1 WHERE is_group_message = 1 AND sender_id != ?",
                [current_user.id]
            )

        elif chat_type == 'direct':
            if not other_id:
                return jsonify({'error': 'user_id requis pour chat direct'}), 400

            messages = c.execute("""
                SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                FROM chat_messages cm
                JOIN users u ON cm.sender_id = u.id
                WHERE cm.is_group_message = 0
                  AND ((cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?))
                ORDER BY cm.created_at DESC
                LIMIT 100
            """, [current_user.id, other_id, other_id, current_user.id]).fetchall()

            c.execute(
                "UPDATE chat_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0",
                [current_user.id, other_id]
            )
        else:
            return jsonify({'error': 'type de chat inconnu'}), 400

        conn.commit()

        msgs = []
        for m in messages:
            msgs.append({
                'id': m['id'],
                'sender_id': m['sender_id'],
                'sender_username': m['username'],
                'sender_fullname': m['full_name'],
                'message': m['message'],
                'created_at': m['created_at'],
                'is_read': bool(m['is_read']),
                'is_own': (m['sender_id'] == current_user.id)
            })

        return jsonify({'messages': list(reversed(msgs))})
        
    except Exception as e:
        print("Erreur chat_messages: {}".format(e))
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/chat/unread_count')
@login_required
def chat_unread_count():
    """Compte des messages non lus"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        direct_row = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id = ? AND is_read = 0 AND is_group_message = 0",
            [current_user.id]
        ).fetchone()
        direct = direct_row['cnt'] if direct_row else 0

        group_row = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message = 1 AND sender_id != ? AND is_read = 0",
            [current_user.id]
        ).fetchone()
        group = group_row['cnt'] if group_row else 0

        users_rows = c.execute("""
            SELECT cm.sender_id, u.username, COUNT(*) as count
            FROM chat_messages cm
            JOIN users u ON cm.sender_id = u.id
            WHERE cm.receiver_id = ? AND cm.is_read = 0 AND cm.is_group_message = 0
            GROUP BY cm.sender_id, u.username
        """, [current_user.id]).fetchall()

        unread_by_user = {}
        for row in users_rows:
            unread_by_user[row['sender_id']] = {'username': row['username'], 'count': row['count']}

        return jsonify({
            'count': int(direct) + int(group),
            'direct': int(direct),
            'group': int(group),
            'by_user': unread_by_user
        })
        
    except Exception as e:
        print("Erreur chat_unread_count: {}".format(e))
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@app.route('/chat/send', methods=['POST'])
@login_required
def chat_send():
    """Envoie un message"""
    try:
        data = request.get_json(force=True)
        msg = (data.get('message') or '').strip()
        ctype = data.get('type', 'direct')
        rid = data.get('receiver_id', None)

        if not msg:
            return jsonify({'error': 'Message vide'}), 400

        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            now_iso = datetime.now().isoformat()
            
            if ctype == 'group':
                c.execute(
                    "INSERT INTO chat_messages (sender_id, message, is_group_message, created_at) VALUES (?, ?, 1, ?)",
                    [current_user.id, msg, now_iso]
                )
            else:
                if not rid:
                    return jsonify({'error': 'Destinataire requis pour chat direct'}), 400
                c.execute(
                    "INSERT INTO chat_messages (sender_id, receiver_id, message, is_group_message, created_at) VALUES (?, ?, ?, 0, ?)",
                    [current_user.id, rid, msg, now_iso]
                )
            
            conn.commit()
            mid = c.lastrowid
            return jsonify({'success': True, 'message_id': mid, 'created_at': now_iso})
            
        except Exception as e:
            print("Erreur chat_send DB: {}".format(e))
            return jsonify({'error': str(e)}), 500
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
                    
    except Exception as e:
        print("Erreur chat_send: {}".format(e))
        return jsonify({'error': 'JSON invalide'}), 400


@app.route('/chat/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    """Marque tous les messages comme lus"""
    try:
        data = request.get_json(force=True)
        chat_type = data.get('type', 'direct')
        user_id = data.get('user_id')

        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            if chat_type == 'group':
                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE is_group_message = 1 AND sender_id != ?",
                    [current_user.id]
                )
            elif chat_type == 'direct' and user_id:
                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_group_message = 0",
                    [current_user.id, user_id]
                )
            else:
                return jsonify({'error': 'Paramètres invalides'}), 400

            conn.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            print("Erreur mark_all_read DB: {}".format(e))
            return jsonify({'error': str(e)}), 500
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
                    
    except Exception as e:
        print("Erreur mark_all_read: {}".format(e))
        return jsonify({'error': 'JSON invalide'}), 400


# ==================== ROUTES SETTINGS ====================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """Paramètres de l'application"""
    if request.method == 'POST':
        name = (request.form.get('company_name') or '').strip()

        if name:
            set_config('company_name', name)
            flash('Nom de l\'entreprise mis à jour', 'success')

        export_password = request.form.get('export_password', '').strip()
        if export_password:
            hashed_password = generate_password_hash(export_password)
            set_config('export_password', hashed_password)
            flash('Mot de passe d\'export configuré avec succès', 'success')

        logo_file = request.files.get('company_logo')
        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(logo_file.filename)
            filename = 'company_' + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logo_file.save(filepath)
            set_config('company_logo', filename)
            flash('Logo uploadé avec succès', 'success')

        return redirect(url_for('settings'))

    current_name = get_config('company_name', 'Inventory Management')
    export_password_set = get_config('export_password', None) is not None
    
    return render_template('settings.html', 
                         company_name=current_name,
                         export_password_set=export_password_set)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Profil utilisateur"""
    if request.method == 'POST':
        cp = request.form.get('current_password', '')
        npw = request.form.get('new_password', '')
        cf = request.form.get('confirm_password', '')
        
        if npw != cf:
            flash('Les mots de passe ne correspondent pas', 'error')
            return render_template('profile.html')
        
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            res = c.execute("SELECT password_hash FROM users WHERE id = ?", [current_user.id]).fetchone()
            
            if res and check_password_hash(res['password_hash'], cp):
                c.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    [generate_password_hash(npw), current_user.id]
                )
                conn.commit()
                flash('Mot de passe modifié', 'success')
            else:
                flash('Mot de passe actuel incorrect', 'error')
        except Exception as e:
            print("Erreur profile: {}".format(e))
            flash('Erreur lors de la modification', 'error')
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    return render_template('profile.html')


# ==================== ROUTES DIVERSES ====================

@app.route('/reset', methods=['GET', 'POST'])
@login_required
@admin_required
def reset_inventory():
    """Réinitialise l'inventaire"""
    if request.method == 'POST':
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM inventory")
            conn.commit()
            flash('Inventaire réinitialisé', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print("Erreur reset_inventory: {}".format(e))
            flash('Erreur lors de la réinitialisation', 'error')
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    return render_template('reset.html')


@app.route('/print/config', methods=['GET', 'POST'])
@login_required
@admin_required
def print_config():
    """Configuration des informations pour l'impression"""
    if request.method == 'POST':
        set_config('print_entreprise', request.form.get('entreprise', ''))
        set_config('print_division', request.form.get('division', ''))
        set_config('print_magasin', request.form.get('magasin', ''))
        set_config('print_zone', request.form.get('zone', ''))
        set_config('print_titre', request.form.get('titre', 'Inventaire Fin 2025'))
        set_config('print_equipe_comptage', request.form.get('equipe_comptage', ''))
        set_config('print_controleur', request.form.get('controleur', ''))
        set_config('print_du', request.form.get('du', ''))
        set_config('print_controleur_gestion', request.form.get('controleur_gestion', ''))

        logo_file = request.files.get('print_logo')
        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(logo_file.filename)
            filename = 'print_logo_' + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logo_file.save(filepath)
            set_config('print_logo', filename)
            flash('Logo uploadé avec succès', 'success')

        flash('Configuration d\'impression enregistrée avec succès', 'success')
        return redirect(url_for('print_config'))

    config_data = {
        'entreprise': get_config('print_entreprise', ''),
        'division': get_config('print_division', ''),
        'magasin': get_config('print_magasin', ''),
        'zone': get_config('print_zone', ''),
        'titre': get_config('print_titre', 'Inventaire Fin 2025'),
        'equipe_comptage': get_config('print_equipe_comptage', ''),
        'controleur': get_config('print_controleur', ''),
        'du': get_config('print_du', ''),
        'controleur_gestion': get_config('print_controleur_gestion', '')
    }

    return render_template('print_config.html', config=config_data)


@app.route('/print/preview')
@login_required
def print_preview():
    """Aperçu avant impression"""
    inventory_data = get_inventory_data()
    config_data = {
        'entreprise': get_config('print_entreprise', get_config('company_name', 'Inventory Management')),
        'division': get_config('print_division', ''),
        'magasin': get_config('print_magasin', ''),
        'zone': get_config('print_zone', ''),
        'titre': get_config('print_titre', 'Inventaire Fin 2025'),
        'equipe_comptage': get_config('print_equipe_comptage', ''),
        'controleur': get_config('print_controleur', ''),
        'du': get_config('print_du', ''),
        'controleur_gestion': get_config('print_controleur_gestion', ''),
        'logo': get_config('company_logo', None)
    }
    stats = get_dashboard_stats()
    
    return render_template('print_preview.html', 
                         inventory_data=inventory_data, 
                         config=config_data,
                         stats=stats,
                         print_date=datetime.now().strftime('%d/%m/%Y'))


@app.route('/update_weights', methods=['POST'])
@login_required
@admin_required
def update_weights():
    """Mise à jour des poids depuis MB52 (deprecated)"""
    flash('Utilisez plutôt la fonction d\'import MB52', 'info')
    return redirect(url_for('mb52_management'))


# ==================== MAIN ====================
if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=False)
