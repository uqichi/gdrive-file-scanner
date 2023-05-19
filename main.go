package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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
	if _, err := os.Stat(clientSecretFile); err != nil {
		log.Fatalf("Unable to find file: %v", err)
	}

	const destDir = "build"
	suffix := time.Now().Format("20060102")
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

const (
	minPageSize = 1
	maxPageSize = 100
)

func pageSize(size int64) int64 {
	if size < minPageSize {
		return minPageSize
	}
	if size > maxPageSize {
		return maxPageSize
	}
	return size
}

func main() {
	// Set commandline args
	asAdmin := flag.Bool("admin", false,
		"ドメイン管理者としてリクエストを発行します。リクエスト元が管理者であるドメインのすべての共有ドライブが返されます。")
	driveID := flag.String("driveId", "",
		"検索する共有ドライブのID。すべての共有ドライブが対象となります。")
	allowDomain := flag.String("allow", "",
		"許可された権限を参照するユーザーまたはグループのメールアドレス。基本的には自社ドメインを指定することになります。")
	flag.Parse()

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
	if err := svc.Drives.List().
		Context(ctx).
		UseDomainAdminAccess(*asAdmin).
		PageSize(pageSize(100)).
		Pages(ctx, func(list *drive.DriveList) error {
			for _, dr := range list.Drives {
				if err := func() error {
					fmt.Printf("Drive: %s (%s)\n", dr.Name, dr.Id)

					if *driveID != "" && *driveID != dr.Id {
						// 共有ドライブIDの指定がある場合該当しないものはスキップ
						fmt.Printf("%cSkipped\n", rune(9))
						return nil
					}

					f, err := os.Create(drivePermPath(dr.Name))
					if err != nil {
						return fmt.Errorf("unable to create file: %v", err)
					}
					defer f.Close()
					permWriter := file.NewDrivePermissionWriter(f)
					defer permWriter.Flush()

					// 共有ドライブの権限情報を取得
					if err := svc.Permissions.List(dr.Id).
						UseDomainAdminAccess(*asAdmin). // Workspace管理者権限で全て取得
						SupportsAllDrives(true).
						PageSize(pageSize(100)).
						Fields("nextPageToken, permissions(id, displayName, emailAddress, role, type, permissionDetails, deleted)").
						Pages(ctx, func(list *drive.PermissionList) error {
							for _, p := range list.Permissions {
								for _, d := range p.PermissionDetails {
									// 共有ドライブの権限情報をファイルに保存
									if err := permWriter.Write(file.DrivePermission{
										Drive:          file.Drive{ID: dr.Id, Name: dr.Name},
										DisplayName:    p.DisplayName,
										EmailAddress:   p.EmailAddress,
										Role:           p.Role,
										Type:           p.Type,
										Deleted:        p.Deleted,
										PermissionType: d.PermissionType,
										InheritedFrom:  d.InheritedFrom,
										Inherited:      d.Inherited,
									}); err != nil {
										return fmt.Errorf("unable to write file: %v", err)
									}
								}
							}
							return nil
						}); err != nil {
						return fmt.Errorf("unable to retrieve permissions: %v", err)
					}

					f, err = os.Create(driveFilePath(dr.Name))
					if err != nil {
						return fmt.Errorf("unable to create file: %v", err)
					}
					defer f.Close()
					fileWriter := file.NewDriveFileWriter(f)
					defer fileWriter.Flush()

					// 共有ドライブのファイルとフォルダのメタ情報を取得
					if err := svc.Files.List().
						SupportsAllDrives(true).
						PageSize(pageSize(100)).
						Corpora("drive").
						DriveId(dr.Id).
						IncludeItemsFromAllDrives(true).
						Fields("nextPageToken, files(mimeType, id, name, webViewLink, createdTime, modifiedTime, lastModifyingUser)").
						Pages(ctx, func(list *drive.FileList) error {
							for _, ff := range list.Files {
								// ファイルとフォルダの権限情報を取得
								if err := svc.Permissions.List(ff.Id).
									UseDomainAdminAccess(*asAdmin).
									SupportsAllDrives(true).
									PageSize(pageSize(100)).
									Fields("nextPageToken, permissions(id, displayName, emailAddress, domain, role, type, permissionDetails, deleted)").
									Pages(ctx, func(list *drive.PermissionList) error {
										for _, p := range list.Permissions {
											for _, d := range p.PermissionDetails {
												if strings.HasSuffix(p.EmailAddress, *allowDomain) {
													// 許可されたドメインはスキップ
													continue
												}
												if strings.HasSuffix(p.Domain, *allowDomain) {
													// 許可されたドメインはスキップ
													continue
												}
												fmt.Printf("%cFile: %s (%s)\n", rune(9), ff.Name, ff.Id)
												// 共有ドライブのファイルとフォルダの情報とその権限情報をファイルに保存
												if err := fileWriter.Write(file.DriveFile{
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
												}); err != nil {
													return fmt.Errorf("unable to write file: %v", err)
												}
											}
										}
										return nil
									}); err != nil {
									return fmt.Errorf("unable to retrieve permission: %v", err)
								}
							}
							return nil
						}); err != nil {
						return fmt.Errorf("unable to retrieve files: %v", err)
					}
					return nil
				}(); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		log.Fatalf("Unable to retrieve drives: %v", err)
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
