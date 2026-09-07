// Package config Docker 绑定校验测试
package config

import "testing"

// TestIsDockerType 验证 Docker 类型判断
func TestIsDockerType(t *testing.T) {
	tests := []struct {
		serverType string
		want       bool
	}{
		{ServerTypeDockerNginx, true},
		{ServerTypeDockerApache, true},
		{ServerTypeNginx, false},
		{ServerTypeApache, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsDockerType(tt.serverType); got != tt.want {
			t.Errorf("IsDockerType(%q) = %v, want %v", tt.serverType, got, tt.want)
		}
	}
}

// TestValidateDockerBinding 验证 Docker 绑定可部署性校验
func TestValidateDockerBinding(t *testing.T) {
	// 非 Docker 类型直接放行
	if err := ValidateDockerBinding(&SiteBinding{ServerType: ServerTypeNginx}); err != nil {
		t.Errorf("非 Docker 绑定不应报错: %v", err)
	}

	// 无 Docker 信息（视为非卷模式）应报错
	if err := ValidateDockerBinding(&SiteBinding{ServerType: ServerTypeDockerNginx}); err == nil {
		t.Error("无 Docker 信息的 Docker 绑定应报错")
	}

	// copy 模式应报错
	copyBinding := &SiteBinding{
		ServerType: ServerTypeDockerNginx,
		Docker:     &DockerInfo{ContainerName: "c1", DeployMode: "copy"},
		Reload:     ReloadConfig{ReloadCommand: "docker exec c1 nginx -s reload"},
	}
	if err := ValidateDockerBinding(copyBinding); err == nil {
		t.Error("copy 模式 Docker 绑定应报错（通用部署路径无法写入）")
	}

	// volume 模式但缺重载命令应报错
	noCmdBinding := &SiteBinding{
		ServerType: ServerTypeDockerNginx,
		Docker:     &DockerInfo{ContainerName: "", DeployMode: "volume"},
	}
	if err := ValidateDockerBinding(noCmdBinding); err == nil {
		t.Error("缺重载命令的 Docker 绑定应报错")
	}

	// volume 模式 + 重载命令，但证书宿主机路径为空（挂载映射解析失败）应报错
	emptyCertBinding := &SiteBinding{
		ServerType: ServerTypeDockerNginx,
		Docker:     &DockerInfo{ContainerName: "c1", DeployMode: "volume"},
		Reload:     ReloadConfig{ReloadCommand: "docker exec c1 nginx -s reload"},
		Paths:      BindingPaths{Certificate: "", PrivateKey: "/host/key.pem"},
	}
	if err := ValidateDockerBinding(emptyCertBinding); err == nil {
		t.Error("证书宿主机路径为空的 volume 绑定应报错（挂载映射解析失败）")
	}

	// volume 模式 + 重载命令，但私钥宿主机路径为空应报错
	emptyKeyBinding := &SiteBinding{
		ServerType: ServerTypeDockerNginx,
		Docker:     &DockerInfo{ContainerName: "c1", DeployMode: "volume"},
		Reload:     ReloadConfig{ReloadCommand: "docker exec c1 nginx -s reload"},
		Paths:      BindingPaths{Certificate: "/host/cert.pem", PrivateKey: ""},
	}
	if err := ValidateDockerBinding(emptyKeyBinding); err == nil {
		t.Error("私钥宿主机路径为空的 volume 绑定应报错（挂载映射解析失败）")
	}

	// volume 模式 + 重载命令 + 证书/私钥宿主机路径齐全 → 放行
	okBinding := &SiteBinding{
		ServerType: ServerTypeDockerNginx,
		Docker:     &DockerInfo{ContainerName: "c1", DeployMode: "volume"},
		Reload:     ReloadConfig{ReloadCommand: "docker exec c1 nginx -s reload"},
		Paths:      BindingPaths{Certificate: "/host/cert.pem", PrivateKey: "/host/key.pem"},
	}
	if err := ValidateDockerBinding(okBinding); err != nil {
		t.Errorf("挂载卷 + 重载命令 + 宿主机路径齐全的 Docker 绑定应放行: %v", err)
	}
}

func TestValidateDockerBinding_CopyNginxRequiresExistingTLSPaths(t *testing.T) {
	for _, tc := range []struct {
		name, serverType, container, certPath, keyPath string
		wantError                                      bool
	}{
		{"nginx", ServerTypeDockerNginx, "web", "/etc/nginx/ssl/cert.pem", "/etc/nginx/ssl/key.pem", false},
		{"apache remains unsupported", ServerTypeDockerApache, "web", "/ssl/cert.pem", "/ssl/key.pem", true},
		{"missing certificate", ServerTypeDockerNginx, "web", "", "/ssl/key.pem", true},
		{"missing private key", ServerTypeDockerNginx, "web", "/ssl/cert.pem", "", true},
		{"relative path", ServerTypeDockerNginx, "web", "ssl/cert.pem", "/ssl/key.pem", true},
		{"same file", ServerTypeDockerNginx, "web", "/ssl/key.pem", "/ssl/key.pem", true},
		{"invalid container", ServerTypeDockerNginx, "web;id", "/ssl/cert.pem", "/ssl/key.pem", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := &SiteBinding{
				ServerType: tc.serverType,
				Docker:     &DockerInfo{ContainerName: tc.container, DeployMode: "copy"},
				Paths:      BindingPaths{Certificate: tc.certPath, PrivateKey: tc.keyPath},
				Reload: ReloadConfig{
					TestCommand:   "docker exec web nginx -t",
					ReloadCommand: "docker exec web nginx -s reload",
				},
			}
			if err := ValidateDockerBinding(binding); (err != nil) != tc.wantError {
				t.Fatalf("ValidateDockerBinding() = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
