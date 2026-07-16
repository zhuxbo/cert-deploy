// Package docker Apache Docker 扫描器宿主机路径解析测试
package docker

import "testing"

// TestResolveHostPaths_FullMount 证书、私钥、证书链均挂载：标记为卷模式，
// 且证书链使用宿主机路径（此前 HostChainPath 计算后无人读取，chain 恒用容器路径）。
func TestResolveHostPaths_FullMount(t *testing.T) {
	client := NewClient("apache123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts: []MountInfo{
			{Type: "bind", Source: "/host/ssl", Destination: "/etc/apache2/ssl", RW: true},
		},
	}

	site := &SSLSite{
		CertificatePath: "/etc/apache2/ssl/cert.pem",
		PrivateKeyPath:  "/etc/apache2/ssl/key.pem",
		ChainPath:       "/etc/apache2/ssl/chain.pem",
	}

	s.resolveHostPaths(site)

	if site.HostCertPath != "/host/ssl/cert.pem" {
		t.Errorf("HostCertPath = %q, want /host/ssl/cert.pem", site.HostCertPath)
	}
	if site.HostKeyPath != "/host/ssl/key.pem" {
		t.Errorf("HostKeyPath = %q, want /host/ssl/key.pem", site.HostKeyPath)
	}
	if site.HostChainPath != "/host/ssl/chain.pem" {
		t.Errorf("HostChainPath = %q, want /host/ssl/chain.pem", site.HostChainPath)
	}
	if !site.VolumeMode {
		t.Error("证书/私钥/链均挂载时 VolumeMode 应为 true")
	}
}

// TestResolveHostPaths_ChainNotMounted 证书与私钥挂载但证书链未挂载：
// 配置了 SSLCertificateChainFile 却无法解析出宿主机链路径，不得标记为卷模式，
// 否则证书链会写到宿主机错误位置。
func TestResolveHostPaths_ChainNotMounted(t *testing.T) {
	client := NewClient("apache123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts: []MountInfo{
			{Type: "bind", Source: "/host/ssl", Destination: "/etc/apache2/ssl", RW: true},
		},
	}

	site := &SSLSite{
		CertificatePath: "/etc/apache2/ssl/cert.pem",
		PrivateKeyPath:  "/etc/apache2/ssl/key.pem",
		ChainPath:       "/etc/apache2/chain/chain.pem", // 未挂载
	}

	s.resolveHostPaths(site)

	if site.HostChainPath != "" {
		t.Errorf("HostChainPath = %q, want empty（证书链未挂载）", site.HostChainPath)
	}
	if site.VolumeMode {
		t.Error("证书链未挂载时 VolumeMode 应为 false")
	}
}

// TestResolveHostPaths_KeyNotMounted 证书挂载但私钥未挂载：不得标记为卷模式。
func TestResolveHostPaths_KeyNotMounted(t *testing.T) {
	client := NewClient("apache123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts: []MountInfo{
			{Type: "bind", Source: "/host/cert", Destination: "/etc/apache2/cert", RW: true},
		},
	}

	site := &SSLSite{
		CertificatePath: "/etc/apache2/cert/cert.pem",
		PrivateKeyPath:  "/etc/apache2/private/key.pem", // 未挂载
	}

	s.resolveHostPaths(site)

	if site.VolumeMode {
		t.Error("私钥未挂载时 VolumeMode 应为 false")
	}
}

// TestResolveHostPaths_NoChainFullMount 无证书链（fullchain 模式）时证书与私钥挂载即卷模式。
func TestResolveHostPaths_NoChainFullMount(t *testing.T) {
	client := NewClient("apache123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts: []MountInfo{
			{Type: "bind", Source: "/host/ssl", Destination: "/etc/apache2/ssl", RW: true},
		},
	}

	site := &SSLSite{
		CertificatePath: "/etc/apache2/ssl/cert.pem",
		PrivateKeyPath:  "/etc/apache2/ssl/key.pem",
		// ChainPath 为空（fullchain 模式）
	}

	s.resolveHostPaths(site)

	if !site.VolumeMode {
		t.Error("无证书链且证书/私钥挂载时 VolumeMode 应为 true")
	}
}
