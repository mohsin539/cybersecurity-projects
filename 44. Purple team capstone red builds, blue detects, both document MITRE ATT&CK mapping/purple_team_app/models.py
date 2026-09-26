from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    role = db.Column(db.String(16), nullable=False, default="red")  # red|blue|admin|auditor
    full_name = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=utcnow)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="planning")  # planning|running|review|closed
    owner = db.Column(db.String(64))
    scope = db.Column(db.Text)
    rules_of_engagement = db.Column(db.Text)
    alignment_score = db.Column(db.Float, default=0.0)
    lessons = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow)
    attacks = db.relationship("RedAttack", backref="case", cascade="all, delete-orphan")
    detections = db.relationship("BlueDetection", backref="case", cascade="all, delete-orphan")

    def recompute_align(self):
        attacks = self.attacks
        if not attacks:
            self.alignment_score = 0.0
            return
        total = 0.0
        for a in attacks:
            d = BlueDetection.query.filter_by(red_attack_id=a.id).first()
            if d is None:
                total += 0.0
            elif d.status == "detected":
                total += 1.0
            elif d.status == "partial":
                total += 0.5
        self.alignment_score = round(total / len(attacks) * 100, 1)


class MitreTechnique(db.Model):
    __tablename__ = "mitre_techniques"
    id = db.Column(db.String(16), primary_key=True)      # e.g. T1003
    name = db.Column(db.String(120), nullable=False)
    tactic = db.Column(db.String(40), nullable=False)
    description = db.Column(db.Text)
    platforms = db.Column(db.String(120))


class RedAttack(db.Model):
    __tablename__ = "red_attacks"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    technique_id = db.Column(db.String(16), db.ForeignKey("mitre_techniques.id"), nullable=False)
    title = db.Column(db.String(200))
    payload = db.Column(db.Text)
    status = db.Column(db.String(20), default="running")  # running|success|failed
    started_at = db.Column(db.DateTime, default=utcnow)
    finished_at = db.Column(db.DateTime)
    telemetry_ref = db.Column(db.String(200))
    technique = db.relationship("MitreTechnique")
    evidence = db.relationship("Evidence", backref="attack", cascade="all, delete-orphan")


class BlueDetection(db.Model):
    __tablename__ = "blue_detections"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    red_attack_id = db.Column(db.Integer, db.ForeignKey("red_attacks.id"), nullable=True)
    technique_id = db.Column(db.String(16), db.ForeignKey("mitre_techniques.id"), nullable=False)
    status = db.Column(db.String(20), default="missed")  # detected|partial|missed
    rule_ref = db.Column(db.String(120))
    alert_ids = db.Column(db.String(200))
    analyst = db.Column(db.String(64))
    detected_at = db.Column(db.DateTime, default=utcnow)
    technique = db.relationship("MitreTechnique")


class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attack_id = db.Column(db.Integer, db.ForeignKey("red_attacks.id"), nullable=False)
    kind = db.Column(db.String(40))  # pcap|screenshot|log|hash
    description = db.Column(db.String(300))
    file_ref = db.Column(db.String(200))
    sha256 = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=utcnow)


class Control(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(16), unique=True)
    title = db.Column(db.String(120))
    description = db.Column(db.String(300))
    iso_ref = db.Column(db.String(16))
    nist_ref = db.Column(db.String(16))
    owasp_ref = db.Column(db.String(8))
    status = db.Column(db.String(16), default="implemented")
    evidence = db.Column(db.String(300))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(64))
    action = db.Column(db.String(200))
    target = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=utcnow)


def audit(actor, action, target=None):
    db.session.add(AuditLog(actor=actor, action=action, target=target))
    db.session.commit()