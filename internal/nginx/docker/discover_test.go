package docker

import (
	"context"
	"testing"
)

func TestIsNginxContainer_ImageMatch(t *testing.T) {
	d := NewDiscoverer("", "")

	tests := []struct {
		name  string
		image string
		want  bool
	}{
		// 应匹配的镜像
		{"nginx latest", "nginx:latest", true},
		{"nginx version", "nginx:1.25", true},
		{"nginx alpine", "nginx:1.25-alpine", true},
		{"nginx plain", "nginx", true},
		{"custom registry nginx", "myregistry.com/nginx:v1", true},
		{"custom registry with port", "myregistry.com:5000/nginx:latest", true},
		{"nginx with prefix", "my-nginx:latest", true},
		{"nginx uppercase", "Nginx:latest", true},
		{"nginx mixed case", "NGINX:1.0", true},
		{"org nginx", "bitnami/nginx:latest", true},
		{"openresty nginx", "openresty/openresty:nginx", true},
		{"nginx-proxy", "nginx-proxy:latest", true},
		{"custom-nginx-image", "custom-nginx-image:v2", true},

		// 不应匹配的镜像（仅基于镜像名；进程检测在无 docker 时也不匹配）
		{"ubuntu", "ubuntu:22.04", false},
		{"redis", "redis:7", false},
		{"mysql", "mysql:8.0", false},
		{"alpine", "alpine:3.18", false},
		{"empty image", "", false},
		{"postgres", "postgres:15", false},
		{"httpd apache", "httpd:2.4", false},
		{"node", "node:18", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 使用空 containerID 触发纯镜像名匹配
			// 非 nginx 镜像会尝试 docker exec（会失败），返回 false
			got := d.isNginxContainer(context.Background(), "nonexistent-container-id", tt.image)
			if got != tt.want {
				t.Errorf("isNginxContainer(_, %q) = %v, want %v", tt.image, got, tt.want)
			}
		})
	}
}

func TestNewDiscoverer(t *testing.T) {
	t.Run("default discoverer", func(t *testing.T) {
		d := NewDiscoverer("", "")
		if d.imageFilter != "" {
			t.Errorf("imageFilter = %q, want empty", d.imageFilter)
		}
		if d.labelFilter != "" {
			t.Errorf("labelFilter = %q, want empty", d.labelFilter)
		}
	})

	t.Run("with filters", func(t *testing.T) {
		d := NewDiscoverer("nginx:latest", "app=web")
		if d.imageFilter != "nginx:latest" {
			t.Errorf("imageFilter = %q, want nginx:latest", d.imageFilter)
		}
		if d.labelFilter != "app=web" {
			t.Errorf("labelFilter = %q, want app=web", d.labelFilter)
		}
	})
}

func TestDiscoveredContainer_Fields(t *testing.T) {
	c := &DiscoveredContainer{
		ID:          "abc123",
		Name:        "my-nginx",
		Image:       "nginx:latest",
		Status:      "Up 2 hours",
		IsCompose:   true,
		ComposeFile: "/path/docker-compose.yml",
		ServiceName: "web",
	}

	if c.ID != "abc123" {
		t.Errorf("ID = %q", c.ID)
	}
	if c.Name != "my-nginx" {
		t.Errorf("Name = %q", c.Name)
	}
	if c.Image != "nginx:latest" {
		t.Errorf("Image = %q", c.Image)
	}
	if c.Status != "Up 2 hours" {
		t.Errorf("Status = %q", c.Status)
	}
	if !c.IsCompose {
		t.Error("expected IsCompose = true")
	}
	if c.ComposeFile != "/path/docker-compose.yml" {
		t.Errorf("ComposeFile = %q", c.ComposeFile)
	}
	if c.ServiceName != "web" {
		t.Errorf("ServiceName = %q", c.ServiceName)
	}
}
