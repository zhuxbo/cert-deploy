package docker

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func TestCopyStagesBothFilesBeforeReplacing(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	t.Setenv("TEST_DOCKER_FAIL_CP", "2")
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: f.KeyPath, DeployMode: "copy"})
	if err := d.deployToContainer(t.Context(), "new-cert", "new-key"); err == nil {
		t.Fatal("第二个文件复制失败时应返回错误")
	}
	f.AssertPair(t, "old-cert", "old-key")
	matches, err := filepath.Glob(filepath.Join(f.Dir, ".sslctl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("暂存文件未清理: %v, %v", matches, err)
	}
}

func TestCopyRejectsSymlinkTarget(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	link := filepath.Join(f.Dir, "linked-key.pem")
	if err := os.Symlink(f.KeyPath, link); err != nil {
		t.Fatal(err)
	}
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: link, DeployMode: "copy"})
	if err := d.deployToContainer(t.Context(), "new-cert", "new-key"); err == nil {
		t.Fatal("符号链接目标不应被覆盖")
	}
	f.AssertPair(t, "old-cert", "old-key")
}

func TestReadContainerFileBoundaries(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "certificate", "private-key")
	client, err := NewRunningClient(t.Context(), "web")
	if err != nil {
		t.Fatal(err)
	}
	file, err := client.ReadRegularFile(t.Context(), f.KeyPath, 11)
	if err != nil || string(file.Data) != "private-key" || file.Mode != 0600 {
		t.Fatalf("读取内容/权限错误: %v", err)
	}
	for _, size := range []int64{0, 10, 11 << 20} {
		if _, err := client.ReadRegularFile(t.Context(), f.KeyPath, size); err == nil {
			t.Fatalf("大小 %d 应拒绝", size)
		}
	}
	if _, err := client.ReadRegularFile(t.Context(), filepath.Join(f.Dir, "missing"), 100); err == nil {
		t.Fatal("缺失文件应拒绝")
	}
	if _, err := NewRunningClient(t.Context(), "bad;name"); err == nil {
		t.Fatal("无效容器名应拒绝")
	}
	t.Setenv("TEST_DOCKER_INFO", `[{"Id":"fixture-id","State":{"Running":false}}]`)
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("停止容器应拒绝")
	}
}

func TestCopyDeployAndRollbackPreservePairAndModes(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: f.KeyPath, DeployMode: "copy"})
	if err := d.Deploy(t.Context(), "new-cert", "chain", "new-key"); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, "new-cert\nchain", "new-key")
	for file, wantMode := range map[string]os.FileMode{f.CertPath: 0644, f.KeyPath: 0600} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("证书部署权限错误: %v, %v", info, err)
		}
	}
	backupDir := t.TempDir()
	certFile, keyFile := filepath.Join(backupDir, "cert.pem"), filepath.Join(backupDir, "key.pem")
	if err := os.WriteFile(certFile, []byte("old-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("old-key"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0640); err != nil {
		t.Fatal(err)
	}
	if err := d.Rollback(t.Context(), certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	info, err := os.Stat(f.KeyPath)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("回滚应恢复原权限: %v", err)
	}
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != "old-cert" {
		t.Fatal("回滚未重载旧证书")
	}
	if err := d.Rollback(t.Context(), filepath.Join(backupDir, "missing"), keyFile); err == nil {
		t.Fatal("缺失证书备份应拒绝")
	}
	if err := d.Rollback(t.Context(), certFile, filepath.Join(backupDir, "missing")); err == nil {
		t.Fatal("缺失私钥备份应拒绝")
	}
}

func TestCopyMountBoundaries(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	c := NewClient("fixture-id")
	cases := []struct {
		name      string
		mounts    []MountInfo
		paths     []string
		wantError bool
	}{
		{"writable-layer", nil, []string{f.CertPath, f.KeyPath}, false},
		{"named-volume", []MountInfo{{Type: "volume", Destination: f.Dir, RW: true}}, []string{f.CertPath, f.KeyPath}, false},
		{"directory-bind", []MountInfo{{Type: "bind", Destination: f.Dir, RW: true}}, []string{f.CertPath}, false},
		{"read-only", []MountInfo{{Type: "volume", Destination: f.Dir, RW: false}}, []string{f.KeyPath}, true},
		{"tmpfs", []MountInfo{{Type: "tmpfs", Destination: f.Dir, RW: true}}, []string{f.CertPath}, true},
		{"single-file", []MountInfo{{Type: "bind", Destination: f.CertPath, RW: true}}, []string{f.CertPath}, true},
		{"root-read-only", []MountInfo{{Type: "bind", Destination: "/", RW: false}}, []string{f.KeyPath}, true},
		{"nested-read-only", []MountInfo{{Type: "bind", Destination: "/", RW: true}, {Type: "bind", Destination: f.Dir, RW: false}}, []string{f.KeyPath}, true},
		{"nested-writable", []MountInfo{{Type: "bind", Destination: f.Dir, RW: true}, {Type: "bind", Destination: "/", RW: false}}, []string{f.KeyPath}, false},
		{"prefix-is-not-parent", []MountInfo{{Type: "bind", Destination: f.Dir + "-other", RW: false}}, []string{f.KeyPath}, false},
		{"second-path-invalid", nil, []string{f.CertPath, "relative/key"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal([]map[string]any{{"Id": "fixture-id", "State": map[string]bool{"Running": true}, "Mounts": tc.mounts}})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEST_DOCKER_INFO", string(data))
			if err := c.CheckCopyPaths(t.Context(), tc.paths...); (err != nil) != tc.wantError {
				t.Fatalf("CheckCopyPaths()=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
	if err := c.CheckCopyPaths(t.Context(), f.KeyPath); err == nil {
		t.Fatal("inspect 失败不能被忽略")
	}
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("不能为 inspect 失败的容器创建运行客户端")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "")
	t.Setenv("TEST_DOCKER_INFO", `[{"Id":"bad;id","State":{"Running":true}}]`)
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("不能使用无效 ID")
	}
}

func TestContainerScriptFailureDoesNotExposeOutput(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	c := NewClient("fixture-id")
	output, err := c.runFileScript(t.Context(), `printf 'private-key-payload'; exit 42`)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 || len(output) != 0 || strings.Contains(err.Error(), "private-key-payload") {
		t.Fatalf("错误必须保留退出原因且不能泄漏输出: bytes=%d error=%v", len(output), err)
	}
	f.WritePair(t, "cert", "key")
	if _, err := c.ReadRegularFile(t.Context(), "relative", 100); err == nil {
		t.Fatal("不能读取相对路径")
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 1); err == nil {
		t.Fatal("超限文件应拒绝")
	}
	if err := os.WriteFile(f.KeyPath, []byte("k"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := c.ReadRegularFile(t.Context(), f.KeyPath, 1); err != nil || string(file.Data) != "k" {
		t.Fatalf("允许边界大小文件: %v", err)
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 10<<20); err != nil {
		t.Fatalf("允许最大请求上限: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.Dir, "bin", "stat"), []byte("#!/bin/sh\nprintf 'invalid-mode\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 100); err == nil {
		t.Fatal("无效权限头应拒绝")
	}
}

func TestCopyRejectsInvalidStagingAndTempFailures(t *testing.T) {
	for _, failure := range []string{"same-path", "missing-key", "host-temp", "stage-command", "stage-outside", "stage-name", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "old-cert", "old-key")
			c := NewClient("fixture-id")
			certPath, keyPath := f.CertPath, f.KeyPath
			var script string
			command := "mktemp"
			switch failure {
			case "same-path":
				keyPath = certPath
			case "missing-key":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "host-temp":
				t.Setenv("TMPDIR", filepath.Join(f.Dir, "missing"))
			case "stage-command":
				script = "#!/bin/sh\nexit 43\n"
			case "stage-outside":
				script = "#!/bin/sh\nprintf '/different/.sslctl-abcd\\n'\n"
			case "stage-name":
				script = "#!/bin/sh\nprintf '%s/invalid-stage\\n' \"$TEST_DOCKER_DIR\"\n"
			case "cleanup":
				command = "rmdir"
				script = "#!/bin/sh\n[ \"$1\" = -- ] && shift\ncase \"$1\" in */.sslctl-lock-*) exec /bin/rmdir \"$@\" ;; *) exit 44 ;; esac\n"
			}
			if script != "" {
				if err := os.WriteFile(filepath.Join(f.Dir, "bin", command), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := c.replaceCertificateFiles(t.Context(), certPath, keyPath, ContainerFile{Data: []byte("new-cert"), Mode: 0644}, ContainerFile{Data: []byte("new-key"), Mode: 0600})
			if err == nil {
				t.Fatal("失败必须返回错误")
			}
			if strings.HasPrefix(failure, "stage-") && failure != "stage-command" && !strings.Contains(err.Error(), "无效暂存目录") {
				t.Fatalf("暂存路径必须在复制前校验: %v", err)
			}
			if failure != "missing-key" && failure != "cleanup" {
				f.AssertPair(t, "old-cert", "old-key")
			}
		})
	}
}
