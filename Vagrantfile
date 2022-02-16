# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/impish64"

  config.vm.synced_folder ".", "/opt/go/src/github.com/mrtc0/bouheki"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y \
      wget \
      curl \
      build-essential \
      libbpf-dev \
      clang \
      llvm \
      zlib1g-dev \
      libelf-dev \
      linux-tools-generic \
      linux-tools-common \
      linux-headers-$(uname -r) \
      linux-tools-$(uname -r) \
      ca-certificates \
      gnupg \
      lsb-release

    # Setup Golang
    wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz -O /tmp/go1.17.5.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go1.17.5.linux-amd64.tar.gz
    echo "PATH=\$PATH:/usr/local/go/bin" > /etc/profile
    mkdir -p /opt/go/{bin,src}
    echo "GOROOT=/opt/go" >> /etc/profile

    # Enable BPF LSM
    sed -i 's/GRUB_CMDLINE_LINUX=\"\"$/GRUB_CMDLINE_LINUX=\"lsm=lockdown,yama,apparmor,bpf\"/' /etc/default/grub
    update-grub

    # Install Docker
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io
  SHELL
end
