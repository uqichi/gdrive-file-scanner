package file

import (
	"encoding/csv"
	"os"
	"strconv"

	"google.golang.org/api/drive/v3"
)

type DriveFileWriter struct {
	writer *csv.Writer
}

func NewDriveFileWriter(file *os.File) *DriveFileWriter {
	writer := &DriveFileWriter{writer: csv.NewWriter(file)}
	// write header
	_ = writer.writer.Write(DriveFile{}.Header())
	return writer
}

func (w *DriveFileWriter) Write(r DriveFile) error {
	return w.writer.Write(r.Record())
}

func (w *DriveFileWriter) Flush() {
	w.writer.Flush()
}

type DriveFile struct {
	MimeType          string
	ID                string
	Name              string
	WebViewLink       string
	CreatedTime       string
	ModifiedTime      string
	LastModifyingUser *drive.User
	Permission        DrivePermission
}

func (DriveFile) Header() []string {
	return []string{
		"MIMEタイプ",
		"ID",
		"名前",
		"リンク",
		"作成日時",
		"最終変更日時",
		"最終変更ユーザー", // MEMO: 本来は作成者を入れたいがなぜか作成者は別APIで取らなきゃいけなそうでコスト高いのでパス
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

func (f DriveFile) Record() []string {
	return []string{
		f.MimeType,
		f.ID,
		f.Name,
		f.WebViewLink,
		f.CreatedTime,
		f.ModifiedTime,
		func() string {
			if f.LastModifyingUser != nil {
				return f.LastModifyingUser.EmailAddress
			}
			return ""
		}(),
		f.Permission.EmailAddress,
		f.Permission.Role,
		f.Permission.Type,
		strconv.FormatBool(f.Permission.Deleted),
		f.Permission.PermissionType,
		f.Permission.Role,
		f.Permission.InheritedFrom,
		strconv.FormatBool(f.Permission.Inherited),
	}
}
