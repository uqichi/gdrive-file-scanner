package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/uqichi/gdrive-file-scanner/file"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const (
	clientSecretFile = "client_credentials.json"
	tokenFile        = "token.json"
)

var (
	buildDirDriveFile string
	buildDirDrivePerm string
)

func init() {
	const destDir = "build"
	suffix := time.Now().Format("20060102150405")
	buildDirDriveFile = fmt.Sprintf("%s_%s/file", destDir, suffix)
	if err := os.MkdirAll(buildDirDriveFile, os.ModePerm); err != nil {
		log.Fatalf("Unable to create directory: %v", err)
	}
	buildDirDrivePerm = fmt.Sprintf("%s_%s/perm", destDir, suffix)
	if err := os.MkdirAll(buildDirDrivePerm, os.ModePerm); err != nil {
		log.Fatalf("Unable to create directory: %v", err)
	}
}

func driveFilePath(name string) string {
	return fmt.Sprintf("%s/%s.csv", buildDirDriveFile, name)
}

func drivePermPath(name string) string {
	return fmt.Sprintf("%s/%s.csv", buildDirDrivePerm, name)
}

func main() {
	ctx := context.Background()
	b, err := os.ReadFile(clientSecretFile)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token file.
	config, err := google.ConfigFromJSON(b, drive.DriveReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	svc, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}

	// 共有ドライブ一覧を取得
	drs, err := svc.Drives.List().
		UseDomainAdminAccess(true). // Workspace管理者権限で全て取得
		Do()
	if err != nil {
		log.Fatalf("Unable to retrieve drives: %v", err)
	}

	for _, dr := range drs.Drives {
		err := func() error {
			fmt.Printf("Drive: %s (%s)\n", dr.Name, dr.Id)

			f, err := os.Create(drivePermPath(dr.Name))
			if err != nil {
				log.Fatalf("Unable to create file: %v", err)
			}
			defer f.Close()

			permWriter := file.NewDrivePermissionWriter(f)
			defer permWriter.Flush()

			// 共有ドライブの権限情報を取得
			perms, err := svc.Permissions.List(dr.Id).
				SupportsAllDrives(true).
				Fields("permissions(id, displayName, emailAddress, role, type, permissionDetails, deleted)").
				Do()
			if err != nil {
				log.Fatalf("Unable to retrieve permissions: %v", err)
			}

			// 共有ドライブの権限情報をファイルに保存
			for _, p := range perms.Permissions {
				for _, d := range p.PermissionDetails {
					_ = permWriter.Write(file.DrivePermission{
						Drive:          file.Drive{ID: dr.Id, Name: dr.Name},
						DisplayName:    p.DisplayName,
						EmailAddress:   p.EmailAddress,
						Role:           p.Role,
						Type:           p.Type,
						Deleted:        p.Deleted,
						PermissionType: d.PermissionType,
						InheritedFrom:  d.InheritedFrom,
						Inherited:      d.Inherited,
					})
				}
			}

			f, err = os.Create(driveFilePath(dr.Name))
			if err != nil {
				log.Fatalf("Unable to create file: %v", err)
			}
			defer f.Close()

			fileWriter := file.NewDriveFileWriter(f)
			defer fileWriter.Flush()

			const pageSize = 100
			var pageToken string
			for {
				// 共有ドライブのファイルとフォルダのメタ情報を取得
				r, err := svc.Files.List().
					Corpora("drive").
					DriveId(dr.Id).
					IncludeItemsFromAllDrives(true).
					PageSize(pageSize).
					PageToken(pageToken).
					SupportsAllDrives(true).
					Fields("nextPageToken, files(mimeType, id, name, webViewLink, createdTime, modifiedTime, lastModifyingUser)").
					Do()
				if err != nil {
					log.Fatalf("Unable to retrieve files: %v", err)
				}

				for _, ff := range r.Files {
					fmt.Printf("%cFile: %s (%s)\n", rune(9), ff.Name, ff.Id)

					// ファイルとフォルダの権限情報を取得
					permissionList, err := svc.Permissions.List(ff.Id).
						SupportsAllDrives(true).
						Fields("permissions(id, displayName, emailAddress, role, type, permissionDetails, deleted)").
						Do()
					if err != nil {
						log.Fatalf("Unable to retrieve permission: %v", err)
					}

					// 共有ドライブのファイルとフォルダの情報と権限情報をファイルに保存
					for _, p := range permissionList.Permissions {
						for _, d := range p.PermissionDetails {
							_ = fileWriter.Write(file.DriveFile{
								MimeType:          ff.MimeType,
								ID:                ff.Id,
								Name:              ff.Name,
								WebViewLink:       ff.WebViewLink,
								CreatedTime:       ff.CreatedTime,
								ModifiedTime:      ff.ModifiedTime,
								LastModifyingUser: ff.LastModifyingUser,
								Permission: file.DrivePermission{
									EmailAddress:   p.EmailAddress,
									Role:           p.Role,
									Type:           p.Type,
									Deleted:        p.Deleted,
									PermissionType: d.PermissionType,
									InheritedFrom:  d.InheritedFrom,
									Inherited:      d.Inherited,
								},
							})
						}
					}
				}
				pageToken = r.NextPageToken
				if pageToken == "" {
					return nil
				}
			}
		}()
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The token file stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tok, err := tokenFromFile(tokenFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokenFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
