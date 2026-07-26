// Package util 文件工具函数测试
package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAtomicWrite 测试原子写入
func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content []byte
		perm    os.FileMode
		wantErr bool
	}{
		{
			name:    "写入普通文件",
			content: []byte("hello world"),
			perm:    0644,
		},
		{
			name:    "写入空文件",
			content: []byte{},
			perm:    0644,
		},
		{
			name:    "写入二进制内容",
			content: []byte{0x00, 0x01, 0x02, 0xff},
			perm:    0600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".txt")

			err := AtomicWrite(path, tt.content, tt.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("AtomicWrite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// 验证文件内容
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			if string(data) != string(tt.content) {
				t.Errorf("file content = %q, want %q", data, tt.content)
			}

			// 验证临时文件不存在
			tmpPath := path + ".tmp"
			if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
				t.Error("temp file should not exist after successful write")
			}
		})
	}
}

// TestAtomicWrite_Overwrite 测试覆盖已存在的文件
func TestAtomicWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.txt")

	// 先写入初始内容
	if err := AtomicWrite(path, []byte("initial"), 0644); err != nil {
		t.Fatalf("initial write failed: %v", err)
	}

	// 覆盖写入
	if err := AtomicWrite(path, []byte("updated"), 0644); err != nil {
		t.Fatalf("overwrite failed: %v", err)
	}

	// 验证内容已更新
	data, _ := os.ReadFile(path)
	if string(data) != "updated" {
		t.Errorf("file content = %q, want %q", data, "updated")
	}
}

// TestAtomicWrite_InvalidPath 测试无效路径
func TestAtomicWrite_InvalidPath(t *testing.T) {
	// 不存在的目录
	err := AtomicWrite("/nonexistent/dir/file.txt", []byte("test"), 0644)
	if err == nil {
		t.Error("AtomicWrite() should fail for nonexistent directory")
	}
}

// TestAtomicWrite_SymlinkTarget 测试目标路径为符号链接时拒绝写入
func TestAtomicWrite_SymlinkTarget(t *testing.T) {
	dir := t.TempDir()

	// 创建一个真实文件
	realFile := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(realFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	// 创建指向真实文件的符号链接
	symlinkPath := filepath.Join(dir, "symlink.txt")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Skip("symlinks not supported")
	}

	// 尝试通过符号链接写入，应该被拒绝
	err := AtomicWrite(symlinkPath, []byte("malicious"), 0644)
	if err == nil {
		t.Error("AtomicWrite() should reject symlink target")
	}
	if err != nil && !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}

	// 验证原始文件内容未被修改
	data, _ := os.ReadFile(realFile)
	if string(data) != "original" {
		t.Errorf("original file was modified through symlink")
	}
}

// TestAtomicWrite_SymlinkTmpFile 测试临时文件路径为符号链接时拒绝写入
func TestAtomicWrite_SymlinkTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	tmpPath := path + ".tmp"

	// 创建一个真实文件作为符号链接目标
	realTmp := filepath.Join(dir, "real_tmp.txt")
	if err := os.WriteFile(realTmp, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	// 注意: os.Remove(tmpPath) 会先被调用清理遗留，然后 O_EXCL 创建新文件
	// 所以即使预先创建了符号链接，Remove 也会删除它，O_EXCL 会创建新的真实文件
	// 这个测试验证整个流程是安全的
	if err := os.Symlink(realTmp, tmpPath); err != nil {
		t.Skip("symlinks not supported")
	}

	// AtomicWrite 会先 Remove(tmpPath) 删除符号链接，然后 O_EXCL 创建新文件
	err := AtomicWrite(path, []byte("safe content"), 0644)
	if err != nil {
		t.Fatalf("AtomicWrite() unexpected error: %v", err)
	}

	// 验证目标文件内容正确
	data, _ := os.ReadFile(path)
	if string(data) != "safe content" {
		t.Errorf("file content = %q, want %q", data, "safe content")
	}

	// 验证原始文件未被修改
	data, _ = os.ReadFile(realTmp)
	if string(data) != "original" {
		t.Error("real_tmp.txt was unexpectedly modified")
	}
}

// TestCopyFile 测试文件复制
func TestCopyFile(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content []byte
		perm    os.FileMode
	}{
		{
			name:    "复制普通文件",
			content: []byte("hello world"),
			perm:    0644,
		},
		{
			name:    "复制空文件",
			content: []byte{},
			perm:    0644,
		},
		{
			name:    "复制带权限的文件",
			content: []byte("secret"),
			perm:    0600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcPath := filepath.Join(dir, "src_"+tt.name+".txt")
			dstPath := filepath.Join(dir, "dst_"+tt.name+".txt")

			// 创建源文件
			if err := os.WriteFile(srcPath, tt.content, tt.perm); err != nil {
				t.Fatalf("failed to create source file: %v", err)
			}

			// 复制文件
			if err := CopyFile(srcPath, dstPath); err != nil {
				t.Fatalf("CopyFile() error = %v", err)
			}

			// 验证目标文件内容
			data, err := os.ReadFile(dstPath)
			if err != nil {
				t.Fatalf("failed to read destination file: %v", err)
			}

			if string(data) != string(tt.content) {
				t.Errorf("destination content = %q, want %q", data, tt.content)
			}
		})
	}
}

// TestCopyFile_SourceNotExist 测试源文件不存在
func TestCopyFile_SourceNotExist(t *testing.T) {
	dir := t.TempDir()
	err := CopyFile(filepath.Join(dir, "nonexistent.txt"), filepath.Join(dir, "dst.txt"))
	if err == nil {
		t.Error("CopyFile() should fail for nonexistent source")
	}
}

// TestCopyFile_InvalidDestination 测试无效目标路径
func TestCopyFile_InvalidDestination(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.txt")

	if err := os.WriteFile(srcPath, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	err := CopyFile(srcPath, "/nonexistent/dir/dst.txt")
	if err == nil {
		t.Error("CopyFile() should fail for invalid destination")
	}
}

// TestCopyFile_DestinationSymlink 验证目标为符号链接时拒绝写入
// （O_TRUNC 会跟随符号链接写到链接目标，与 AtomicWrite 防护对齐）。
func TestCopyFile_DestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.txt")
	realTarget := filepath.Join(dir, "real-target.txt")
	linkPath := filepath.Join(dir, "dst-link.txt")

	if err := os.WriteFile(srcPath, []byte("new-content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realTarget, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTarget, linkPath); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}

	if err := CopyFile(srcPath, linkPath); err == nil {
		t.Error("目标为符号链接时应拒绝写入")
	}

	// 链接指向的真实文件不得被篡改
	data, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Error("符号链接目标文件被篡改（防护未生效）")
	}
}

// TestFileExists 测试文件存在检查
func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "exists.txt")

	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"存在的文件", existingFile, true},
		{"不存在的文件", filepath.Join(dir, "notexists.txt"), false},
		{"存在的目录", dir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileExists(tt.path); got != tt.want {
				t.Errorf("FileExists(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestEnsureDir 测试目录创建
func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
		perm os.FileMode
	}{
		{"创建单级目录", filepath.Join(dir, "single"), 0755},
		{"创建多级目录", filepath.Join(dir, "a/b/c"), 0755},
		{"创建已存在目录", dir, 0755},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EnsureDir(tt.path, tt.perm); err != nil {
				t.Errorf("EnsureDir() error = %v", err)
			}

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("directory not created: %v", err)
			}

			if !info.IsDir() {
				t.Error("path is not a directory")
			}
		})
	}
}

// TestJoinUnderDir 测试安全路径拼接
func TestJoinUnderDir(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		path    string
		wantErr bool
		check   func(t *testing.T, result string)
	}{
		{
			name:    "正常拼接",
			baseDir: "/var/www",
			path:    "html/index.html",
			check: func(t *testing.T, result string) {
				t.Helper()
				if !strings.HasSuffix(result, "html/index.html") {
					t.Errorf("result = %s, should end with html/index.html", result)
				}
			},
		},
		{
			name:    "带前导斜杠的路径",
			baseDir: "/var/www",
			path:    "/html/index.html",
			check: func(t *testing.T, result string) {
				t.Helper()
				if !strings.HasPrefix(result, "/var/www") {
					t.Errorf("result = %s, should start with /var/www", result)
				}
			},
		},
		{
			name:    "URL 风格路径",
			baseDir: "/var/www",
			path:    "/.well-known/acme-challenge/token",
			check: func(t *testing.T, result string) {
				t.Helper()
				if !strings.HasPrefix(result, "/var/www") {
					t.Errorf("result = %s, should start with /var/www", result)
				}
			},
		},
		{
			name:    "路径穿越 ..",
			baseDir: "/var/www",
			path:    "../etc/passwd",
			wantErr: true,
		},
		{
			name:    "深层路径穿越",
			baseDir: "/var/www",
			path:    "html/../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "绝对路径",
			baseDir: "/var/www",
			path:    "/etc/passwd",
			check: func(t *testing.T, result string) {
				t.Helper()
				// 前导斜杠会被去除，所以应该可以正常拼接
				if !strings.HasPrefix(result, "/var/www") {
					t.Errorf("result = %s, should start with /var/www", result)
				}
			},
		},
		{
			name:    "空 baseDir",
			baseDir: "",
			path:    "test.txt",
			wantErr: true,
		},
		{
			name:    "空 path",
			baseDir: "/var/www",
			path:    "",
			wantErr: true,
		},
		{
			name:    "只有空格的 path",
			baseDir: "/var/www",
			path:    "   ",
			wantErr: true,
		},
		{
			name:    "点路径",
			baseDir: "/var/www",
			path:    ".",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := JoinUnderDir(tt.baseDir, tt.path)

			if (err != nil) != tt.wantErr {
				t.Errorf("JoinUnderDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// TestSafeReadFile 测试安全读取文件
func TestSafeReadFile(t *testing.T) {
	dir := t.TempDir()

	// 准备普通文件
	normalFile := filepath.Join(dir, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	// 准备大文件（100 字节）
	largeFile := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(largeFile, make([]byte, 100), 0644); err != nil {
		t.Fatal(err)
	}

	// 准备符号链接
	symlinkFile := filepath.Join(dir, "symlink.txt")
	symlinkErr := os.Symlink(normalFile, symlinkFile)

	tests := []struct {
		name       string
		path       string
		maxSize    int64
		wantErr    bool
		errContain string
		wantData   string
	}{
		{
			name:     "正常读取普通文件",
			path:     normalFile,
			maxSize:  1024,
			wantData: "hello",
		},
		{
			name:     "maxSize=0 不限制大小",
			path:     normalFile,
			maxSize:  0,
			wantData: "hello",
		},
		{
			name:       "文件不存在",
			path:       filepath.Join(dir, "nonexistent.txt"),
			maxSize:    1024,
			wantErr:    true,
			errContain: "lstat",
		},
		{
			name:       "文件超过 maxSize",
			path:       largeFile,
			maxSize:    50,
			wantErr:    true,
			errContain: "file too large",
		},
		{
			name:       "目录而非文件",
			path:       dir,
			maxSize:    1024,
			wantErr:    true,
			errContain: "not a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := SafeReadFile(tt.path, tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeReadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errContain)
				}
				return
			}
			if string(data) != tt.wantData {
				t.Errorf("data = %q, want %q", data, tt.wantData)
			}
		})
	}

	// 符号链接单独测试（跳过不支持的平台）
	t.Run("符号链接拒绝读取", func(t *testing.T) {
		if symlinkErr != nil {
			t.Skip("symlinks not supported")
		}
		_, err := SafeReadFile(symlinkFile, 1024)
		if err == nil {
			t.Error("SafeReadFile() should reject symlinks")
		}
		if err != nil && !strings.Contains(err.Error(), "symbolic links not allowed") {
			t.Errorf("error = %q, want containing %q", err.Error(), "symbolic links not allowed")
		}
	})
}

// TestSafeReadFile_MaxSizeBoundary 测试 maxSize 边界情况
func TestSafeReadFile_MaxSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boundary.txt")
	content := []byte("12345") // 5 字节

	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	// maxSize 正好等于文件大小，应该成功
	data, err := SafeReadFile(path, 5)
	if err != nil {
		t.Errorf("SafeReadFile() with exact maxSize should succeed, got error: %v", err)
	}
	if string(data) != "12345" {
		t.Errorf("data = %q, want %q", data, "12345")
	}

	// maxSize 比文件小 1 字节，应该失败
	_, err = SafeReadFile(path, 4)
	if err == nil {
		t.Error("SafeReadFile() should fail when file exceeds maxSize")
	}
}

// TestJoinUnderDir_RealPath 使用真实临时目录测试
func TestJoinUnderDir_RealPath(t *testing.T) {
	dir := t.TempDir()

	result, err := JoinUnderDir(dir, "subdir/file.txt")
	if err != nil {
		t.Fatalf("JoinUnderDir() error = %v", err)
	}

	expected := filepath.Join(dir, "subdir", "file.txt")
	if result != expected {
		t.Errorf("result = %s, want %s", result, expected)
	}
}
