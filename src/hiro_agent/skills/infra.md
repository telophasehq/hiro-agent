# Infrastructure & Deployment

## What to investigate

- Read all Dockerfiles, docker-compose files, and `.dockerignore`
- Read Kubernetes manifests — deployments, services, ingress, network policies, RBAC
- Read Terraform/CloudFormation/Pulumi for cloud resource configuration
- Check security groups, firewall rules, IAM policies
- Read database connection config — SSL, credentials, public accessibility
- Check deployment configs for environment variable overrides (debug mode, feature flags)

## What to grep for in Dockerfiles

```
FROM.*:latest                     # Unpinned base image
USER root|# no USER directive     # Running as root
RUN.*chmod.*777                   # World-writable permissions
RUN.*curl.*|.*sh|RUN.*wget.*|.*bash  # Piped install scripts
ADD\s                             # Should use COPY (ADD auto-extracts/fetches)
ARG.*(PASSWORD|SECRET|TOKEN|KEY)  # Secrets as build args (in image history)
ENV.*(PASSWORD|SECRET|KEY)=       # Hardcoded secrets in env
EXPOSE\s+22                       # SSH in containers
COPY.*\.env|COPY.*\.git|COPY\s+\.\s+\.  # Secrets copied into image
```

## What to grep for in Kubernetes manifests

```
privileged:\s*true                # Full host access
hostNetwork:\s*true               # Host network namespace
hostPID:\s*true                   # Host process namespace
allowPrivilegeEscalation:\s*true  # Can escalate
runAsUser:\s*0                    # Running as root
docker.sock                       # Docker socket mount (container escape)
automountServiceAccountToken:\s*true  # Default SA token (usually unnecessary)
cluster-admin                     # Overprivileged RBAC binding
image:.*:latest                   # Unpinned image tag
```

## What to grep for in cloud config (Terraform/CloudFormation)

```
# Network exposure
cidr_blocks.*"0.0.0.0/0"         # Unrestricted ingress
from_port.*22\b|from_port.*3389   # SSH/RDP open to internet
from_port.*3306|from_port.*5432   # Databases open to internet
from_port.*6379|from_port.*27017  # Redis/MongoDB open
from_port.*0.*to_port.*65535     # All ports open

# IAM/permissions
"Action":\s*"\*"|"Action":\s*"s3:\*"   # Overprivileged IAM
"Resource":\s*"\*"                      # Wildcard resource
"Principal":\s*"\*"                     # Public access

# Storage
acl.*"public-read"|acl.*"public-read-write"  # Public buckets
block_public_acls.*false                      # Public access not blocked
publicly_accessible.*true                     # Public database

# Encryption
encrypted.*false|storage_encrypted.*false     # Unencrypted storage
kms_key_id                                    # Should be present for custom keys

# Logging
enable_logging.*false|log_file_validation_enabled.*false
```

## What to look for

- Containers running as root (missing `USER` directive)
- Debug mode enabled in production (`DEBUG=True`, `NODE_ENV=development`)
- Exposed ports that should be internal-only (databases, caches, admin panels)
- Permissive CORS (`Access-Control-Allow-Origin: *` with credentials)
- Missing TLS between services or to databases
- Overprivileged IAM — roles with `*` actions or resources
- Public cloud storage buckets (S3, GCS, Azure Blob)
- Databases publicly accessible from the internet
- Missing network policies in Kubernetes (all pod-to-pod traffic allowed by default)
- Missing resource limits on containers (CPU/memory) — DoS risk
- Security headers missing (`HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `CSP`)
- Missing `.dockerignore` — build context may include secrets
- CI/CD deploys from unpinned or mutable image tags

## Cross-reference with application code

- Check if debug mode defaults in code are overridden by deployment environment
- Check if the app binds to `0.0.0.0` and whether the container/service exposes it correctly
- Check if the app expects network-level access control that the infra actually enforces
- Check if the app uses internal service URLs that are actually reachable from outside
- Check if the app's CORS config matches what the reverse proxy/gateway allows
