# CTF Instance Manager

**CTF Instance Manager** is a lightweight, Python-based orchestration API designed to deploy isolated, on-demand Docker containers for Capture The Flag (CTF) competitions.

It allows administrators to register challenge "blueprints" and enables users to spin up their own private instance of a challenge (Web or Netcat), ensuring that one player's actions do not affect another's gameplay.

## 🚀 Features

- **On-Demand Deployment:** Users click "Initialize" to spawn a fresh, isolated Docker container.
- **Multi-Node Architecture:** Supports a centralized Controller with multiple Worker Nodes via Docker Context/SSH.
- **Dynamic Routing:**
  - **Web Challenges:** Automatically generates Nginx reverse proxy configs for `challenge-uuid.yourdomain.com`.
  - **Netcat Challenges:** Assigns random high ports and provides direct `nc <ip> <port>` connection strings.
- **Resource Management:**
  - **Anti-Hoarding:** Strict 2-hour limit on instance lifetime.
  - **Auto-Cleanup:** Background scheduler kills expired containers to free up RAM.
  - **Soft Stops:** "Zombie" state preserves user session data in the DB while stopping the container to save resources, allowing for quick restarts.
- **Admin Panel:** Web-based dashboard to register new challenges, monitor active instances in real-time, and force-terminate containers.
- **Concurrency Safe:** Implements file locking (`fcntl`) to ensure the background scheduler runs on only a single Gunicorn worker.

## 🛠️ Architecture

The system consists of two main components:

1.  **Controller (Main Node):**
    - Runs the Flask Application (API & Frontend).
    - Runs Nginx (Reverse Proxy & SSL Termination).
    - Manages the SQLite Database.
2.  **Workers (Compute Nodes):**
    - Dumb Docker hosts accessed via SSH.
    - Run the actual challenge containers.
    - Expose random high ports (10000-20000) back to the Controller.

## 📋 Prerequisites

- **Python 3.8+**
- **Docker** (installed on Main and Worker nodes)
- **Nginx** (on Main node)
- **SSH Access** (Key-based auth between Main and Workers)

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone [https://github.com/yourusername/ctf-instance-manager.git](https://github.com/yourusername/ctf-instance-manager.git)
cd ctf-instance-manager
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configuration

Edit `main.py` to configure your Worker Nodes and Domain. Ensure you use absolute paths for the SQLite database to avoid Gunicorn routing issues.

### 4. Running with Gunicorn (Production)

```bash
gunicorn --workers 1 --threads 4 --bind unix:ctf.sock -m 007 main:app
```

## 🖥️ Usage

### Admin Panel

1. Navigate to `/admin_login`.
2. Create a Challenge Blueprint:
   - **Docker Slug:** The image name on Docker Hub.
   - **Internal Port:** The port the container listens on (e.g., 80 or 1337).
   - **Type:** Select `Website` (HTTP) or `Netcat` (TCP).

### User Flow

1. User clicks **"Initialize"** on the dashboard.
2. System deploys the container to a worker node.
3. User receives a unique URL or `nc` command.
4. User can extend the time by 30-minute increments (up to 2 hours total).

## ⚠️ Security Note

- **Network Isolation:** Challenge workers should be on an isolated network.
- **Secrets:** Use environment variables for sensitive IP addresses and SSH credentials.

## 📄 License

[MIT License](LICENSE)
