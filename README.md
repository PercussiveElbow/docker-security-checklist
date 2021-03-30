# Docker Security Checklist

For a more thorough checklist please refer to the latest Docker [CIS benchmark](https://www.cisecurity.org/benchmark/docker/)

### Patching
* Ensure you patch your Docker daemon/containerd etc to protect against escape CVEs such as 
  * CVE-2019-5736
  * CVE-2019-14271
  * CVE-2020–15257
* Follow appropriate [Docker security updates](https://www.docker.com/blog/tag/docker-security/)

### Image security
* Conduct image vulnerability scanning using an appropriate scanner such as Anchore, Claire or Trivy.
* Use only trusted images and consider utilising Docker [content trust](https://docs.docker.com/engine/security/trust/)

### Runtime security
* Do not run containers as root users
* Utilise [user namespaces](https://docs.docker.com/engine/security/userns-remap/)
* Do not use host network mode.
* Do not use privileged mode.
* Drop capabilities if they're not needed
* Do not mount the Docker unix socket in your containers (*/var/run/docker.sock*)
* Consider read-only container filesystems.

### Logging
* Ensure your containers log to an appropriate log driver and ensure this is being appropriately monitored.

### Daemon security
* Use [rootless Docker](https://docs.docker.com/engine/security/rootless/) (experimental)
* Use SELinux/apparmor etc

### API and socket security
* Take care to protect /var/run/docker.sock with appropriate filesystem protects. 
* Do not grant permissions to the Docker group unless you are OK with that user being root
* Do not expose the TCP Docker socket publicly.
  * [Protect the TCP socket with HTTPS](https://docs.docker.com/engine/security/https/)
  * Implement an authorisation/authentication solution for this.
  
### Docker in your CI pipeline/building images safely
* Consider using [Kaniko](https://github.com/GoogleContainerTools/kaniko) to build your containers in userspace.

