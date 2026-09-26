export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
}

export interface Campaign {
  id: number;
  name: string;
  vector: string;
  status: string;
  schedule_at: string | null;
  created_at: string;
  sent: number;
  opened: number;
  clicked: number;
  submitted: number;
  reported: number;
}

export interface Dashboard {
  total_employees: number;
  total_campaigns: number;
  total_sent: number;
  total_opened: number;
  total_clicked: number;
  total_submitted: number;
  total_reported: number;
  avg_se_index: number;
  campaigns: Campaign[];
  top_risk: RiskRow[];
}

export interface RiskRow {
  employee_code: string;
  full_name: string;
  branch: string;
  se_index: number;
  clicks: number;
  submissions: number;
  trainings_ok: boolean;
}

export interface Employee {
  id: number;
  employee_code: string;
  full_name: string;
  email: string;
  phone: string;
  branch: string;
  division: string;
  job_grade: string;
  risk_weight: number;
  opt_out: boolean;
}

export interface Delivery {
  id: number;
  employee_code: string;
  full_name: string;
  branch: string;
  status: string;
  open_url: string;
  click_url: string;
  sent_at: string | null;
  opened_at: string | null;
  clicked_at: string | null;
  submitted_at: string | null;
  reported_at: string | null;
}

export interface Report {
  id: number;
  name: string;
  fmt: string;
  size: number;
  status: string;
  url_token: string;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  target_type: string;
  target_id: number | null;
  detail: string;
  hash: string;
  created_at: string;
}

export interface LureTemplate {
  id: number;
  name: string;
  language: string;
  subject: string;
  body_html: string;
}

export interface LandingPage {
  id: number;
  name: string;
  title: string;
  body_html: string;
}

export interface Training {
  id: number;
  employee_id: number;
  title: string;
  completed: boolean;
  score: number;
  created_at: string;
}