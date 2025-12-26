# Docker: Run RedAudit on Windows or macOS

## What is Docker and Why Use It?

**Docker** is like a "virtual box" that runs Linux applications on any computer. Since RedAudit is designed for Linux, Docker lets you use it on **Windows** or **macOS** without any complex setup.

**Benefits:**

- ✅ No need to install Linux
- ✅ No dependencies to configure
- ✅ Works exactly the same everywhere
- ✅ Easy to update (just pull a new image)

---

# macOS Guide

## Step 1: Install Docker Desktop

1. **Go to**: <https://www.docker.com/products/docker-desktop/>
2. **Click** the **Download** button
   - If you have a newer Mac (M1, M2, M3, M4): choose **"Mac with Apple chip"**
   - If you have an older Intel Mac: choose **"Mac with Intel chip"**
   - *Not sure? Click Apple menu → "About This Mac" → check if it says "Apple M1/M2/M3" or "Intel"*
3. **Open** the downloaded `.dmg` file
4. **Drag** the Docker icon to your Applications folder
5. **Open** Docker from your Applications folder
6. **Click "Open"** when macOS asks for permission
7. **Accept** the license agreement
8. **Skip** or close the tutorial/sign-in prompts (you don't need an account)
9. **Wait** until you see a **green indicator** in the top menu bar (the whale icon)

> 💡 **Tip**: Docker may ask for your password to install components. This is normal.

## Step 2: Open Terminal

1. Press **Cmd + Space** (opens Spotlight)
2. Type **Terminal**
3. Press **Enter**

A black/white window will open. This is where you'll type commands.

## Step 3: Download RedAudit

Copy and paste this command into Terminal, then press **Enter**:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

You'll see download progress. This downloads about 500MB and takes 1-5 minutes depending on your internet.

## Step 4: Create a Folder for Reports

```bash
mkdir -p ~/RedAudit-Reports
```

This creates a folder in your home directory where scan reports will be saved.

## Step 5: Run RedAudit (Interactive Wizard)

This is the **recommended way** for first-time users:

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**What this command does:**

- `docker run` - starts a container
- `-it` - makes it interactive (you can type)
- `--rm` - cleans up after you're done
- `-v ~/RedAudit-Reports:/reports` - saves reports to your folder
- The last part is the RedAudit image

**The wizard will guide you through:**

1. Selecting your language (English/Spanish)
2. Entering the target network (e.g., `192.168.1.0/24`)
3. Choosing scan mode (quick/normal/deep)
4. Additional options

> 💡 **Finding your network**: Run `ipconfig getifaddr en0` to see your IP. If it's `192.168.1.50`, your network is probably `192.168.1.0/24`.

## Step 6: View Reports

When the scan finishes, open the HTML report:

```bash
open ~/RedAudit-Reports/report.html
```

This opens a beautiful, interactive report in your web browser.

---

# Windows Guide

## Step 1: Install Docker Desktop

1. **Go to**: <https://www.docker.com/products/docker-desktop/>
2. **Click** "Download for Windows"
3. **Run** the downloaded installer (`Docker Desktop Installer.exe`)
4. **Follow** the installation prompts (keep default settings)
5. **Restart** your computer when asked
6. **Open** Docker Desktop from the Start menu
7. **Skip** the tutorial and account creation (not required)
8. **Wait** until you see a **green indicator** in the system tray (bottom-right, whale icon)

> ⚠️ **Windows 10/11 Home users**: Docker may ask you to install WSL2. Follow the prompts to install it - this is required.

## Step 2: Open PowerShell

1. Press **Win + X**
2. Click **"Windows PowerShell"** or **"Terminal"**

A blue/black window will open.

## Step 3: Download RedAudit

Copy and paste this command, then press **Enter**:

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Wait for the download to complete (1-5 minutes).

## Step 4: Create a Folder for Reports

```powershell
mkdir C:\RedAudit-Reports
```

## Step 5: Run RedAudit (Interactive Wizard)

This is the **recommended way** for first-time users:

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**The wizard will guide you through everything:**

1. Select language
2. Enter target network
3. Choose scan mode
4. Start scanning

> 💡 **Finding your network**: Run `ipconfig` and look for "IPv4 Address". If it's `192.168.1.50`, your network is `192.168.1.0/24`.

## Step 6: View Reports

1. Open **File Explorer**
2. Navigate to `C:\RedAudit-Reports`
3. Double-click `report.html`

---

# Quick Reference

## Most Common Commands

| What you want to do | Command |
|---------------------|---------|
| **Start wizard** (recommended) | `docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest` |
| Update to latest version | `docker pull ghcr.io/dorinbadea/redaudit:latest` |
| Show help | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Check version | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |

## Troubleshooting

### "Cannot connect to Docker daemon"

Docker Desktop isn't running. Open Docker Desktop and wait for the green indicator.

### "No matching manifest for linux/arm64"

You have an older image. Run:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### Scans not finding hosts

On Windows/macOS, Docker runs in a virtual environment and may not see all local network devices. Try scanning specific IPs instead of ranges.

---

# Linux Users

If you're on Linux, you don't need Docker! Install RedAudit natively:

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

If you still want Docker on Linux (for isolation):

```bash
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

The `--network host` flag gives full network visibility (only works on Linux).
