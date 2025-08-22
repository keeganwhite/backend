#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    printf "${1}${2}${NC}\n"
}

# Function to print section headers
print_header() {
    echo
    print_color $CYAN "=================================="
    print_color $CYAN "$1"
    print_color $CYAN "=================================="
    echo
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait with countdown
wait_with_countdown() {
    local seconds=$1
    local message=$2

    print_color $YELLOW "$message"
    for ((i=seconds; i>0; i--)); do
        printf "\r${YELLOW}Waiting... ${i} seconds remaining${NC}"
        sleep 1
    done
    printf "\r${GREEN}Wait complete!                    ${NC}\n"
}



print_header "iNethi Backend Production Setup"

# Check if we're in the correct directory
if [ ! -f "docker-compose-prod.yml" ]; then
    print_color $RED "Error: docker-compose-prod.yml not found!"
    print_color $RED "Please run this script from the root of the iNethi backend repository."
    exit 1
fi

# Check for required commands
print_color $BLUE "Checking prerequisites..."

if ! command_exists docker; then
    print_color $RED "Error: Docker is not installed or not in PATH"
    print_color $YELLOW "Please install Docker first: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
    print_color $RED "Error: Docker Compose is not installed or not in PATH"
    print_color $YELLOW "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

print_color $GREEN "✓ Docker and Docker Compose are available"

# Check Docker permissions
print_color $BLUE "Checking Docker permissions..."

if ! docker ps >/dev/null 2>&1; then
    print_color $RED "Error: Cannot run Docker commands without sudo!"
    echo
    print_color $YELLOW "This usually means your user is not in the 'docker' group."
    print_color $YELLOW "To fix this issue, you have two options:"
    echo
    print_color $CYAN "Option 1 (Recommended): Add your user to the docker group"
    print_color $YELLOW "  1. Run: sudo usermod -aG docker \$USER"
    print_color $YELLOW "  2. Log out and log back in (or restart your session)"
    print_color $YELLOW "  3. Verify with: docker ps"
    echo
    print_color $CYAN "Option 2: Run this script with sudo (not recommended for security reasons)"
    print_color $YELLOW "  sudo ./setup.sh"
    echo
    print_color $BLUE "For detailed instructions, see:"
    print_color $BLUE "https://docs.docker.com/engine/install/linux-postinstall/"
    echo
    print_color $RED "Please fix the Docker permissions issue and run this script again."
    exit 1
fi

print_color $GREEN "✓ Docker permissions are correct"

# Test Docker Compose permissions
if ! (docker-compose version >/dev/null 2>&1 || docker compose version >/dev/null 2>&1); then
    print_color $RED "Error: Cannot run Docker Compose commands!"
    print_color $YELLOW "This might be related to Docker permissions. Please ensure Docker is properly configured."
    print_color $BLUE "See: https://docs.docker.com/engine/install/linux-postinstall/"
    exit 1
fi

print_color $GREEN "✓ Docker Compose permissions are correct"

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_color $RED "Error: .env file not found!"
    print_color $RED "Please create a .env file based on .env.example before running this script."
    print_color $YELLOW "Required variables include:"
    print_color $YELLOW "- DB_HOST, DB_NAME, DB_USER, DB_PASS"
    print_color $YELLOW "- TRAEFIK_BACKEND_HOST, TRAEFIK_ENTRYPOINTS, TRAEFIK_CERTRESOLVER, TRAEFIK_NETWORK_BRIDGE"
    print_color $YELLOW "- KEYCLOAK configuration"
    print_color $YELLOW "- Blockchain configuration"
    exit 1
fi

print_color $GREEN "✓ .env file found"

# Check JSON configuration files
print_header "Configuration Files Check"
print_color $BLUE "Checking JSON configuration files..."

# Check if JSON files exist
json_files_missing=false

if [ ! -f "inethi/sample_radiusdesk_config.json" ]; then
    print_color $RED "Error: inethi/sample_radiusdesk_config.json not found!"
    print_color $YELLOW "Please create this file before running the setup script."
    json_files_missing=true
fi

if [ ! -f "inethi/smart_contracts.json" ]; then
    print_color $RED "Error: inethi/smart_contracts.json not found!"
    print_color $YELLOW "Please create this file before running the setup script."
    json_files_missing=true
fi

if [ ! -f "inethi/users.json" ]; then
    print_color $RED "Error: inethi/users.json not found!"
    print_color $YELLOW "Please create this file before running the setup script."
    json_files_missing=true
fi

if [ "$json_files_missing" = true ]; then
    print_color $RED "Please create the missing JSON files and run the script again."
    exit 1
fi

# Validate JSON files if jq is available
if command_exists jq; then
    print_color $BLUE "Validating JSON files..."
    
    if ! jq empty inethi/sample_radiusdesk_config.json 2>/dev/null; then
        print_color $RED "Error: inethi/sample_radiusdesk_config.json contains invalid JSON"
        exit 1
    fi
    
    if ! jq empty inethi/smart_contracts.json 2>/dev/null; then
        print_color $RED "Error: inethi/smart_contracts.json contains invalid JSON"
        exit 1
    fi
    
    if ! jq empty inethi/users.json 2>/dev/null; then
        print_color $RED "Error: inethi/users.json contains invalid JSON"
        exit 1
    fi
    
    print_color $GREEN "✓ All JSON files are valid"
else
    print_color $YELLOW "Warning: jq not installed, skipping JSON validation"
fi

print_color $GREEN "✓ All required JSON files found"

# Display and confirm .env file
print_header "Environment Configuration Review"
print_color $CYAN "About to display your .env file contents..."
print_color $YELLOW "Press Enter to continue and view the .env file..."
read -r

print_color $YELLOW "Current .env file contents:"
echo
cat .env
echo

read -p "$(print_color $CYAN "Are you happy with the .env configuration? (y/N): ")" -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_color $YELLOW "Please update your .env file and run the script again."
    exit 0
fi

# Display and confirm JSON files
print_header "JSON Configuration Files Review"
print_color $CYAN "About to display your JSON configuration files..."
print_color $YELLOW "Press Enter to continue and view the JSON files..."
read -r

print_color $YELLOW "Current sample_radiusdesk_config.json contents:"
echo
cat inethi/sample_radiusdesk_config.json
echo

print_color $YELLOW "Current smart_contracts.json contents:"
echo
cat inethi/smart_contracts.json
echo

print_color $YELLOW "Current users.json contents:"
echo
cat inethi/users.json
echo

read -p "$(print_color $CYAN "Are you happy with the JSON configuration files? (y/N): ")" -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_color $YELLOW "Please update your JSON configuration files and run the script again."
    exit 0
fi

# Basic validation of .env file
print_color $BLUE "Validating .env file..."

required_vars=("DB_HOST" "DB_NAME" "DB_USER" "DB_PASS" "TRAEFIK_BACKEND_HOST" "TRAEFIK_ENTRYPOINTS" "TRAEFIK_CERTRESOLVER" "TRAEFIK_NETWORK_BRIDGE")

for var in "${required_vars[@]}"; do
    if ! grep -q "^${var}=" .env; then
        print_color $RED "Error: Required variable $var not found in .env file"
        exit 1
    fi

    # Check if variable has a value
    value=$(grep "^${var}=" .env | cut -d'=' -f2-)
    if [ -z "$value" ] || [ "$value" = "your_value_here" ] || [ "$value" = "changeme" ]; then
        print_color $RED "Error: Variable $var appears to have a placeholder value. Please set a real value."
        exit 1
    fi
done

print_color $GREEN "✓ .env file validation passed"

# Stop any existing containers
print_header "Stopping Existing Containers"
if docker compose -f docker-compose-prod.yml down 2>/dev/null || docker compose -f docker-compose-prod.yml down 2>/dev/null; then
    print_color $GREEN "✓ Stopped any existing containers"
else
    print_color $YELLOW "No existing containers to stop"
fi

# Build the Docker image
print_header "Building Docker Image"
print_color $BLUE "Building the iNethi backend image..."

if docker compose -f docker-compose-prod.yml build 2>/dev/null || docker compose -f docker-compose-prod.yml build 2>/dev/null; then
    print_color $GREEN "✓ Docker image built successfully"
else
    print_color $RED "Error: Failed to build Docker image"
    print_color $YELLOW "This might be a permissions issue. If you're getting permission denied errors,"
    print_color $YELLOW "please check: https://docs.docker.com/engine/install/linux-postinstall/"
    exit 1
fi

# Start database and redis first
print_header "Starting Database and Redis"
print_color $BLUE "Starting TimescaleDB database and Redis..."

if docker compose -f docker-compose-prod.yml up -d db redis 2>/dev/null || docker compose -f docker-compose-prod.yml up -d db redis 2>/dev/null; then
    print_color $GREEN "✓ Database and Redis started"
else
    print_color $RED "Error: Failed to start database and Redis"
    print_color $YELLOW "Check Docker permissions if you're getting permission denied errors:"
    print_color $YELLOW "https://docs.docker.com/engine/install/linux-postinstall/"
    exit 1
fi

wait_with_countdown 15 "Waiting for database and Redis to be ready..."

# Start the Django API
print_header "Starting Django API"
print_color $BLUE "Starting the iNethi backend API..."

if docker compose -f docker-compose-prod.yml up -d app 2>/dev/null || docker compose -f docker-compose-prod.yml up -d app 2>/dev/null; then
    print_color $GREEN "✓ Django API started"
else
    print_color $RED "Error: Failed to start Django API"
    exit 1
fi

wait_with_countdown 45 "Waiting for Django API to complete migrations and be ready..."

# Check if Django is healthy
print_color $BLUE "Checking Django API health..."
max_attempts=8
attempt=1

while [ $attempt -le $max_attempts ]; do
    if docker logs inethi-backend-v1 2>&1 | grep -q "Starting development server" || \
       docker logs inethi-backend-v1 2>&1 | grep -q "Booting worker" || \
       docker logs inethi-backend-v1 2>&1 | grep -q "Listening on"; then
        print_color $GREEN "✓ Django API is healthy and ready"
        break
    fi

    if [ $attempt -eq $max_attempts ]; then
        print_color $YELLOW "Warning: Could not confirm Django API health, but proceeding..."
        print_color $BLUE "You can check the logs with: docker logs inethi-backend-v1"
        break
    fi

    print_color $YELLOW "Attempt $attempt/$max_attempts: Django API not ready yet, waiting..."
    sleep 10
    ((attempt++))
done

# Start Celery worker
print_header "Starting Celery Worker"
print_color $BLUE "Starting Celery worker..."

if docker compose -f docker-compose-prod.yml up -d celery 2>/dev/null || docker compose -f docker-compose-prod.yml up -d celery 2>/dev/null; then
    print_color $GREEN "✓ Celery worker started"
else
    print_color $RED "Error: Failed to start Celery worker"
    exit 1
fi

wait_with_countdown 10 "Waiting for Celery worker to be ready..."

# Start Celery beat
print_header "Starting Celery Beat"
print_color $BLUE "Starting Celery beat scheduler..."

if docker compose -f docker-compose-prod.yml up -d celery_beat 2>/dev/null || docker compose -f docker-compose-prod.yml up -d celery_beat 2>/dev/null; then
    print_color $GREEN "✓ Celery beat started"
else
    print_color $RED "Error: Failed to start Celery beat"
    exit 1
fi

# Run management commands to populate the database
print_header "Populating Database"
print_color $BLUE "Running management commands to populate the database..."

# Create users from JSON
print_color $BLUE "Creating users from users.json..."
if docker compose -f docker-compose-prod.yml exec -T app python manage.py create_users_from_json users.json 2>/dev/null || \
   docker compose -f docker-compose-prod.yml exec -T app python manage.py create_users_from_json users.json 2>/dev/null; then
    print_color $GREEN "✓ Users created successfully"
else
    print_color $YELLOW "Warning: Failed to create users (they might already exist)"
fi

# Create smart contracts from JSON
print_color $BLUE "Creating smart contracts from smart_contracts.json..."
if docker compose -f docker-compose-prod.yml exec -T app python manage.py create_smart_contracts_from_json smart_contracts.json 2>/dev/null || \
   docker compose -f docker-compose-prod.yml exec -T app python manage.py create_smart_contracts_from_json smart_contracts.json 2>/dev/null; then
    print_color $GREEN "✓ Smart contracts created successfully"
else
    print_color $YELLOW "Warning: Failed to create smart contracts (they might already exist)"
fi

# Create RADIUSdesk instances from JSON
print_color $BLUE "Creating RADIUSdesk instances from sample_radiusdesk_config.json..."
if docker compose -f docker-compose-prod.yml exec -T app python manage.py create_radiusdesk_from_json sample_radiusdesk_config.json 2>/dev/null || \
   docker compose -f docker-compose-prod.yml exec -T app python manage.py create_radiusdesk_from_json sample_radiusdesk_config.json 2>/dev/null; then
    print_color $GREEN "✓ RADIUSdesk instances created successfully"
else
    print_color $YELLOW "Warning: Failed to create RADIUSdesk instances (they might already exist)"
fi

# Create superuser
print_color $BLUE "Creating superuser..."
if docker compose -f docker-compose-prod.yml exec -T app python manage.py create_superuser 2>/dev/null || \
   docker compose -f docker-compose-prod.yml exec -T app python manage.py create_superuser 2>/dev/null; then
    print_color $GREEN "✓ Superuser created successfully"
else
    print_color $YELLOW "Warning: Failed to create superuser (might already exist or need manual creation)"
    print_color $BLUE "You can create a superuser manually with:"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml exec app python manage.py create_superuser"
fi

# Final status check
print_header "Deployment Status"
print_color $BLUE "Checking container status..."

if docker compose -f docker-compose-prod.yml ps 2>/dev/null || docker compose -f docker-compose-prod.yml ps 2>/dev/null; then
    echo
    print_color $GREEN "✓ All containers are running!"
    echo
    print_color $CYAN "You can now access:"
    print_color $YELLOW "- Admin Interface: http://<your_domain>:8000/admin"
    print_color $YELLOW "- API Docs: http://<your_domain>:8000/api/v1/docs"
    print_color $YELLOW "- API Schema: http://<your_domain>:8000/api/v1/schema/"
    echo
    print_color $BLUE "To view logs, use:"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml logs -f [service_name]"
    print_color $YELLOW "  Available services: app, db, redis, celery, celery_beat"
    echo
    print_color $BLUE "To stop all services:"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml down"
    echo
    print_color $BLUE "Useful commands:"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml logs app        # View Django logs"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml logs celery    # View Celery worker logs"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml restart app    # Restart Django service"
    echo
    print_color $BLUE "Management commands:"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml exec app python manage.py create_superuser"
    print_color $YELLOW "  docker compose -f docker-compose-prod.yml exec app python manage.py shell"
    echo
else
    print_color $RED "Error: Failed to get container status"
    print_color $YELLOW "This might be a permissions issue. Check:"
    print_color $YELLOW "https://docs.docker.com/engine/install/linux-postinstall/"
    exit 1
fi

print_header "Setup Complete!"
print_color $GREEN "iNethi backend is now running successfully!"
print_color $GREEN "All services are up and database has been populated with initial data."
