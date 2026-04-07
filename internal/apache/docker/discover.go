// Package docker 提供 Apache Docker 容器扫描支持
package docker

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	nginxDocker "github.com/zhuxbo/sslctl/internal/nginx/docker"
)

// DiscoveredContainer 发现的 Apache 容器
type DiscoveredContainer = nginxDocker.DiscoveredContainer

// DiscoverApacheContainers 发现所有 Apache 容器
func DiscoverApacheContainers(ctx context.Context) ([]*DiscoveredContainer, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var containers []*DiscoveredContainer

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var info struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Image  string `json:"Image"`
			Status string `json:"Status"`
		}

		if err := json.Unmarshal([]byte(line), &info); err != nil {
			continue
		}

		if !isApacheContainer(ctx, info.ID, info.Image) {
			continue
		}

		container := &DiscoveredContainer{
			ID:     info.ID,
			Name:   info.Names,
			Image:  info.Image,
			Status: info.Status,
		}

		// 检测 compose 信息
		if composeFile, serviceName := detectComposeInfo(ctx, info.ID); composeFile != "" {
			container.IsCompose = true
			container.ComposeFile = composeFile
			container.ServiceName = serviceName
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// isApacheContainer 检查是否是 Apache 容器
func isApacheContainer(ctx context.Context, containerID, image string) bool {
	// 方法1: 镜像名包含 apache/httpd
	imageLower := strings.ToLower(image)
	if strings.Contains(imageLower, "apache") || strings.Contains(imageLower, "httpd") {
		return true
	}

	// 方法2: 检查 httpd/apache2 进程
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	for _, proc := range []string{"httpd", "apache2"} {
		cmd := exec.CommandContext(checkCtx, "docker", "exec", containerID, "pgrep", "-x", proc)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// 方法3: 检查命令是否存在
	for _, bin := range []string{"httpd", "apachectl", "apache2ctl"} {
		cmd := exec.CommandContext(checkCtx, "docker", "exec", containerID, "which", bin)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	return false
}

// detectComposeInfo 检测 compose 配置信息
func detectComposeInfo(ctx context.Context, containerID string) (composeFile, serviceName string) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}",
		containerID)

	output, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// CheckDockerAvailable 检查 docker 命令是否可用
func CheckDockerAvailable() bool {
	return nginxDocker.CheckDockerAvailable()
}
