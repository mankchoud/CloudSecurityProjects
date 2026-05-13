# Cloud Security Projects

**Hands-on AWS security engineering across two projects: secure VPC design with Infrastructure as Code, and a DevSecOps CI/CD pipeline with security gates at every stage.**

Both projects run entirely on the **AWS Free Tier**. Every production tool that costs money has been substituted with an open-source equivalent, documented with the production equivalent and the reason for the substitution.

---

## Projects

| # | Project | Key Skills | Tools |
|---|---|---|---|
| 1 | [VPC Infrastructure as Code](#project-2-vpc-infrastructure-as-code) | Network security, Terraform, defence in depth | Terraform, AWS VPC, EC2, CloudWatch |
| 2 | [CI/CD Pipeline With Security Built In](#project-3-cicd-pipeline-with-security-built-in) | DevSecOps, shift-left security, IaC scanning | GitHub Actions, Gitleaks, Semgrep, Checkov, Trivy |

---

## Project 1: VPC Infrastructure as Code

### What Was Built

A production-grade, multi-tier VPC on AWS, built entirely with Terraform. Security is designed into the architecture — not bolted on afterwards. The network is segmented into three tiers with genuine isolation between them.

```
Internet → IGW → Nginx Proxy (public) → App Server (private) → Database (data)
                 [replaces ALB]
                 NAT Instance (public) ← outbound updates from App Server
                 [replaces NAT Gateway]
```

### Architecture

| Tier | Subnets | Internet Access | What Lives Here |
|---|---|---|---|
| Public | 10.0.1.0/24, 10.0.2.0/24 | Full (via IGW) | Nginx proxy, NAT Instance |
| Private | 10.0.10.0/24, 10.0.20.0/24 | Outbound only (via NAT) | Application server |
| Data | 10.0.100.0/24, 10.0.200.0/24 | **None** | Databases (isolated) |

Both AZs are provisioned in Terraform. Only AZ-A has running instances — AZ-B subnets exist for HA scaling.

### Security Controls

**Security Groups — instance level, stateful, SG-to-SG references:**
```
nginx-sg (80/443 from internet)
  → app-sg (8080 from nginx-sg only)
    → db-sg (5432 from app-sg only)
```
App servers and databases accept traffic only from the immediately upstream tier — not from CIDRs, not from the internet.

**Network ACLs — subnet level, stateless, explicit deny:**
- Public NACL: allow 80/443 + ephemeral return ports
- Private NACL: allow 8080 from public subnets + explicit deny all else
- Data NACL: allow 5432 from private subnets only + explicit deny all inbound/outbound

**VPC Flow Logs:**
- All traffic metadata → CloudWatch Logs (7-day retention)
- All traffic metadata → S3 (30-day lifecycle, AES-256 encrypted, public access blocked)
- Query rejected traffic in CloudWatch Logs Insights to detect port scans and misconfigurations

**VPC Endpoints (Gateway type — free):**
- S3 Gateway Endpoint with account-scoped endpoint policy
- DynamoDB Gateway Endpoint
- Data tier resources reach S3/DynamoDB without internet route

### Free-Tier Substitutions

| Production Resource | Substitute Used | Production Cost |
|---|---|---|
| NAT Gateway ×2 (one per AZ) | NAT Instance — t2.micro EC2 | ~$64/mo |
| Application Load Balancer | Nginx reverse proxy — t2.micro EC2 | ~$18/mo |
| Athena (S3 log analysis) | CloudWatch Logs Insights | $5/TB scanned |
| Interface VPC Endpoints | Gateway Endpoints only (S3, DynamoDB) | ~$7/mo each |

Every substitution is commented in the Terraform with the production equivalent and the reason.

### Terraform File Map

| File | Purpose |
|---|---|
| `main.tf` | Provider, local backend, AMI + AZ data sources |
| `vpc.tf` | VPC, all 6 subnets, Internet Gateway |
| `routing.tf` | 3 route tables — public→IGW, private→NAT, data→local only |
| `nat.tf` | NAT Instance + EIP, IP forwarding, iptables masquerade, SSM role |
| `security_groups.tf` | SG chain (nginx→app→db) + all EC2 instances |
| `nacls.tf` | Stateless subnet-level ACLs, explicit deny on data tier |
| `endpoints.tf` | S3 + DynamoDB Gateway Endpoints with restrictive policy |
| `flow_logs.tf` | Flow Logs → CloudWatch + S3, encryption, lifecycle |
| `variables.tf` | All input variables |
| `outputs.tf` | IPs, IDs, and SSM access commands |

### Key Design Decisions

**Why private subnets?** App servers have no public IP. An attacker who finds the Nginx IP still cannot reach the app server — it requires breaking through the nginx-sg, then through the app-sg. The database has no internet route at all: even a fully compromised app server cannot exfiltrate directly to the internet from the data tier.

**Why SG references instead of CIDRs?** If the Nginx instance is replaced (new IP, new instance), the app-sg rule still works because it references the security group, not the IP address. No rule update needed.

**Why two layers (SGs + NACLs)?** Defence in depth. If a security group is accidentally misconfigured to allow broad access, the NACL provides a subnet-wide backstop. The data subnet NACL explicitly denies all traffic except PostgreSQL from private subnet CIDRs — three independent layers protect the database.

**NAT Instance source/destination check:** Must be disabled. AWS drops packets where the instance is neither the source nor the destination. NAT forwards packets on behalf of other instances — so this check must be off. Forgetting this is the most common reason NAT instances appear to work but silently drop all traffic.

---

## Project 2: CI/CD Pipeline With Security Built In

### What Was Built

A complete DevSecOps pipeline using GitHub Actions. Security checks run automatically on every push and pull request, catching vulnerabilities before they reach production. The pipeline directly scans the Terraform code from Project 2 — connecting both projects.

### Pipeline Flow

```
Developer → Pre-commit hook (Gitleaks + tf fmt) → push to GitHub
                                                        │
                                        ┌───────────────▼───────────────┐
                                        │   security-scan.yml           │
                                        │   on: push, pull_request      │
                                        └───────────────────────────────┘
                                                        │
                                              Step 2: Gitleaks
                                              (full history scan)
                                                        │
                                         ┌──────────────┼──────────────┐
                                         │              │              │
                                    Step 3:        Step 4:        Step 5:
                                    Semgrep        pip-audit      Checkov
                                    (SAST)         npm audit      (IaC scan)
                                         │              │              │
                                         └──────────────┼──────────────┘
                                                        │
                                              Security Summary
                                              (if: always())
                                                        │
                                              ┌─────────┴──────────┐
                                              │                    │
                                         All pass           Any fail
                                              │                    │
                                        Merge allowed       PR blocked
```

### Security Checks

**1. Secret Scanning — Gitleaks OSS**
- Runs on the pre-commit hook (staged files only, fast) and in CI (full history)
- Detects AWS keys, GitHub tokens, private keys, passwords, API keys
- Blocks: any detected secret
- Production equivalent: GitHub Advanced Security push protection

**2. SAST — Semgrep OSS**
- Rule sets: `p/security-audit`, `p/python`, `p/javascript`, `p/terraform`, `p/secrets`
- SARIF results uploaded to GitHub Security → Code scanning tab (findings inline on PR diff)
- Blocks: ERROR severity (HIGH/CRITICAL)
- Warns: WARNING severity (pipeline continues)
- Production equivalent: SonarQube Cloud, GitHub CodeQL

**3. Dependency Scanning — pip-audit + npm audit**
- Queries PyPA Advisory Database and OSV (Google)
- Custom parser (`scripts/scan-results-parser.sh`) applies blocking logic
- Blocks: CRITICAL CVEs with no available fix
- Warns: HIGH CVEs where a fix exists
- Production equivalent: Snyk, OWASP Dependency-Check

**4. IaC Scanning — Checkov OSS + tfsec OSS**
- Scans all Terraform files from Project 2
- `policies/checkov-config/checkov.yaml` contains the skip list — every skipped check has a documented reason and the production fix
- Blocks: MEDIUM/HIGH/CRITICAL failed checks
- Separate `terraform-check.yml` workflow also runs tfsec, `terraform fmt`, and `terraform validate`
- Production equivalent: Checkov + Terraform Sentinel

**5. Container Scanning — Trivy OSS**
- Image built locally inside the runner — never pushed to ECR (zero ECR cost)
- Scans OS packages, application dependencies, and Dockerfile misconfigurations
- Blocks: CRITICAL/HIGH vulnerabilities, container running as root
- Production equivalent: AWS ECR enhanced scanning, Amazon Inspector

### Block vs Warn Logic

| Finding | Action |
|---|---|
| Any secret | BLOCK |
| SQL / command injection (Semgrep ERROR) | BLOCK |
| S3 public access (Checkov) | BLOCK |
| CRITICAL CVE with no fix (pip-audit) | BLOCK |
| Container running as root (Trivy) | BLOCK |
| MEDIUM dependency CVE | WARN — pipeline continues |
| Code quality findings | WARN — pipeline continues |
| Informational | WARN — pipeline continues |
| Documented false positive | Suppressed — inline comment + exception file |

### Free-Tier Substitutions

| Production Tool | Substitute Used | Cost Saved |
|---|---|---|
| GitHub Advanced Security | Gitleaks + Semgrep OSS | ~$19/user/mo |
| SonarQube Cloud | Semgrep OSS | ~$15/mo+ |
| Snyk team tier | pip-audit + npm audit | ~$25/user/mo |
| AWS ECR scanning | Trivy (local, never pushed) | ~$0.09/image |
| Amazon Inspector | Trivy (local in runner) | ~$0.002/hr |
| AWS CodePipeline | GitHub Actions | ~$1/pipeline/mo |
| AWS CodeBuild | GitHub-hosted runners | $0.005/build-min |

**Total monthly cost: $0**

### Workflow File Map

| File | Purpose |
|---|---|
| `.github/workflows/security-scan.yml` | Main pipeline — all 5 check types |
| `.github/workflows/terraform-check.yml` | IaC-only — Checkov, tfsec, fmt, validate |
| `.github/workflows/container-scan.yml` | Container — Trivy CVE + Dockerfile scan |
| `policies/checkov-config/checkov.yaml` | Skip list with documented reasons |
| `policies/checkov-config/tfsec.yaml` | tfsec exclude list |
| `policies/semgrep-rules/no-hardcoded-credentials.yaml` | Custom SAST rules |
| `policies/exceptions/adding-exceptions.md` | Exception process + register |
| `policies/exceptions/TEMPLATE.md` | Exception file template |
| `scripts/pre-commit-hook.sh` | Local: Gitleaks + tf fmt + file size |
| `scripts/scan-results-parser.sh` | pip-audit parser — exits 1 on CRITICAL |
| `docs/tool-configuration.md` | Tool config + production upgrade path |
| `docs/escalation-process.md` | What to do when a check blocks a PR |

---

## How the Two Projects Connect

Project 3 scans the Terraform code from Project 2. When the IaC workflow triggers on a `.tf` file change, Checkov and tfsec analyse the VPC architecture — security groups, NACLs, flow log configuration, S3 bucket settings, IAM roles. The pipeline either approves the infrastructure change or blocks it with a specific finding.

This is the DevSecOps loop: infrastructure is treated like application code, reviewed by automated security tools on every change, with findings surfaced before anything is deployed.

---

## Running the Projects

### Project 2 — Deploy the VPC

```bash
cd 02-vpc-infrastructure-as-code/terraform/

# Initialise (downloads AWS provider)
terraform init

# Preview what will be created
terraform plan

# Deploy
terraform apply

# Verify: curl the Nginx proxy
curl http://<nginx_public_ip>

# Access instances via SSM (no SSH port required)
aws ssm start-session --target <instance-id>

# Tear down when finished (stops free-tier instance hours)
terraform destroy
```

### Project 3 — Activate the Pipeline

```bash
# 1. Push the project to a GitHub repository

# 2. Install the pre-commit hook locally
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 3. Install Gitleaks locally (for the pre-commit hook)
#    Mac:     brew install gitleaks
#    Windows: choco install gitleaks
#    Linux:   https://github.com/gitleaks/gitleaks#installing

# 4. The GitHub Actions workflows run automatically on push and PR
#    No configuration needed — all tools run on GitHub-hosted runners
```

---

## Prerequisites

- AWS account (free tier)
- AWS CLI configured (`aws configure`)
- Terraform >= 1.6.0
- Git

See `02-vpc-infrastructure-as-code/docs/architecture.md` for the full setup guide.

---

## Repository Structure

```
cloud-security-projects/
├── 01-vpc-infrastructure-as-code/
│   ├── README.md
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── vpc.tf
│   │   ├── routing.tf
│   │   ├── nat.tf
│   │   ├── security_groups.tf
│   │   ├── nacls.tf
│   │   ├── endpoints.tf
│   │   ├── flow_logs.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── terraform.tfvars
│   └── docs/
│       ├── architecture.md
│       └── security-decisions.md
└── 02-cicd-security-pipeline/
    ├── README.md
    ├── .github/
    │   └── workflows/
    │       ├── security-scan.yml
    │       ├── terraform-check.yml
    │       └── container-scan.yml
    ├── policies/
    │   ├── semgrep-rules/
    │   ├── checkov-config/
    │   └── exceptions/
    ├── scripts/
    │   ├── pre-commit-hook.sh
    │   └── scan-results-parser.sh
    └── docs/
        ├── tool-configuration.md
        └── escalation-process.md
```
