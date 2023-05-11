package file

import (
	"encoding/csv"
	"os"
	"strconv"
)

type DrivePermissionWriter struct {
	writer *csv.Writer
}

func NewDrivePermissionWriter(file *os.File) *DrivePermissionWriter {
	writer := &DrivePermissionWriter{writer: csv.NewWriter(file)}
	// write header
	_ = writer.writer.Write(DrivePermission{}.Header())
	return writer
}

func (w *DrivePermissionWriter) Write(r DrivePermission) error {
	return w.writer.Write(r.Record())
}

func (w *DrivePermissionWriter) Flush() {
	w.writer.Flush()
}

type DrivePermission struct {
	Drive          Drive
	DisplayName    string
	EmailAddress   string
	Role           string
	Type           string
	Deleted        bool
	PermissionType string
	InheritedFrom  string
	Inherited      bool
}

func (DrivePermission) Header() []string {
	return []string{
		"共有ドライブのID",
		"共有ドライブの名前",
		"この権限を参照するユーザーまたはグループの名前",
		"この権限を参照するユーザーまたはグループのメールアドレス",
		"この権限によって付与されるロール",
		"譲受人の種類",
		"この権限に関連付けられたアカウントが削除されているかどうか",
		"このユーザーの権限タイプ",
		"このユーザーのメインのロール",
		"この権限の継承元であるアイテムのID",
		"この権限を継承しているかどうか",
	}
}

func (p DrivePermission) Record() []string {
	return []string{
		p.Drive.ID,
		p.Drive.Name,
		p.DisplayName,
		p.EmailAddress,
		p.Role,
		p.Type,
		strconv.FormatBool(p.Deleted),
		p.PermissionType,
		p.Role,
		p.InheritedFrom,
		strconv.FormatBool(p.Inherited),
	}
}
