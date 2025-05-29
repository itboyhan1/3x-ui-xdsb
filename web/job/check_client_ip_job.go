package job

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"slices"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/web/service"
	"x-ui/logger"
	"x-ui/xray"
)

type CheckClientIpJob struct {
	lastClear     int64
	disAllowedIps []string
}

// DeviceFingerprint 设备指纹结构体
type DeviceFingerprint struct {
	ID             string    `json:"id"`             // 设备唯一标识
	UserAgent      string    `json:"userAgent"`      // User-Agent字符串
	TLSFingerprint string    `json:"tlsFingerprint"` // TLS指纹
	FirstSeen      time.Time `json:"firstSeen"`      // 首次出现时间
	LastSeen       time.Time `json:"lastSeen"`       // 最后活跃时间
	IPAddresses    []string  `json:"ipAddresses"`    // 关联的IP地址列表
}

var job *CheckClientIpJob

func NewCheckClientIpJob() *CheckClientIpJob {
	job = new(CheckClientIpJob)
	return job
}

func (j *CheckClientIpJob) Run() {
	if j.lastClear == 0 {
		j.lastClear = time.Now().Unix()
	}

	shouldClearAccessLog := false
	iplimitActive := j.hasLimitOrDeviceLimit() // 修改：检查LimitIP或MaxDevices
	f2bInstalled := j.checkFail2BanInstalled()
	isAccessLogAvailable := j.checkAccessLogAvailable(iplimitActive)

	if iplimitActive {
		if f2bInstalled && isAccessLogAvailable {
			shouldClearAccessLog = j.processLogFile()
		} else {
			if !f2bInstalled {
				logger.Warning("[LimitIP/MaxDevices] Fail2Ban is not installed, Please install Fail2Ban from the x-ui bash menu.")
			}
		}
	}

	if shouldClearAccessLog || (isAccessLogAvailable && time.Now().Unix()-j.lastClear > 3600) {
		j.clearAccessLog()
	}
}

func (j *CheckClientIpJob) clearAccessLog() {
	logAccessP, err := os.OpenFile(xray.GetAccessPersistentLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	j.checkError(err)

	accessLogPath, err := xray.GetAccessLogPath()
	j.checkError(err)

	file, err := os.Open(accessLogPath)
	j.checkError(err)

	_, err = io.Copy(logAccessP, file)
	j.checkError(err)

	logAccessP.Close()
	file.Close()

	err = os.Truncate(accessLogPath, 0)
	j.checkError(err)
	j.lastClear = time.Now().Unix()
}

func (j *CheckClientIpJob) hasLimitOrDeviceLimit() bool { // 修改函数名和逻辑
	db := database.GetDB()
	var inbounds []*model.Inbound

	err := db.Model(model.Inbound{}).Find(&inbounds).Error
	if err != nil {
		return false
	}

	for _, inbound := range inbounds {
		if inbound.Settings == "" {
			continue
		}

		settings := map[string][]model.Client{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients := settings["clients"]

		for _, client := range clients {
			limitIp := client.LimitIP
			maxDevices := client.MaxDevices // 新增：获取MaxDevices
			if limitIp > 0 || maxDevices > 0 { // 修改：检查LimitIP或MaxDevices
				return true
			}
		}
	}

	return false
}

func (j *CheckClientIpJob) processLogFile() bool {

	ipRegex := regexp.MustCompile(`from (?:tcp:|udp:)?\[?([0-9a-fA-F\.:]+)\]?:\d+ accepted`)
	emailRegex := regexp.MustCompile(`email: (.+)$`)
	// 添加User-Agent和TLS指纹的正则表达式
	userAgentRegex := regexp.MustCompile(`user-agent: ([^\s]+)`)
	tlsFingerprintRegex := regexp.MustCompile(`tls-fingerprint: ([^\s]+)`)

	accessLogPath, _ := xray.GetAccessLogPath()
	file, _ := os.Open(accessLogPath)
	defer file.Close()

	inboundClientIps := make(map[string]map[string]struct{}, 100)
	// 添加设备指纹映射
	inboundClientFingerprints := make(map[string]map[string]*DeviceFingerprint, 100)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		ipMatches := ipRegex.FindStringSubmatch(line)
		if len(ipMatches) < 2 {
			continue
		}

		ip := ipMatches[1]

		if ip == "127.0.0.1" || ip == "::1" {
			continue
		}

		emailMatches := emailRegex.FindStringSubmatch(line)
		if len(emailMatches) < 2 {
			continue
		}
		email := emailMatches[1]

		// 提取User-Agent和TLS指纹
		userAgent := ""
		tlsFingerprint := ""
		if uaMatches := userAgentRegex.FindStringSubmatch(line); len(uaMatches) >= 2 {
			userAgent = uaMatches[1]
		}
		if tlsMatches := tlsFingerprintRegex.FindStringSubmatch(line); len(tlsMatches) >= 2 {
			tlsFingerprint = tlsMatches[1]
		}

		// 生成设备指纹ID
		deviceID := j.generateDeviceFingerprint(userAgent, tlsFingerprint)

		// 存储IP映射（保持原有逻辑）
		if _, exists := inboundClientIps[email]; !exists {
			inboundClientIps[email] = make(map[string]struct{})
		}
		inboundClientIps[email][ip] = struct{}{}

		// 存储设备指纹映射
		if userAgent != "" || tlsFingerprint != "" {
			if _, exists := inboundClientFingerprints[email]; !exists {
				inboundClientFingerprints[email] = make(map[string]*DeviceFingerprint)
			}
			if fingerprint, exists := inboundClientFingerprints[email][deviceID]; exists {
				// 更新现有指纹
				fingerprint.LastSeen = time.Now()
				if !j.contains(fingerprint.IPAddresses, ip) {
					fingerprint.IPAddresses = append(fingerprint.IPAddresses, ip)
				}
			} else {
				// 创建新指纹
				inboundClientFingerprints[email][deviceID] = &DeviceFingerprint{
					ID:             deviceID,
					UserAgent:      userAgent,
					TLSFingerprint: tlsFingerprint,
					FirstSeen:      time.Now(),
					LastSeen:       time.Now(),
					IPAddresses:    []string{ip},
				}
			}
		}
	}

	shouldCleanLog := false
	db := database.GetDB()
	var clientInboundID int

	for email, uniqueIps := range inboundClientIps {
		var clientData model.Client
		// Find the client by email. This requires iterating through inbounds and their clients.
		// This is a simplified representation. In a real scenario, you'd need a more efficient way to get client by email.
		foundClient := false
		var allInbounds []*model.Inbound
		db.Find(&allInbounds)
		for _, inbound := range allInbounds {
			if inbound.Settings == "" {
				continue
			}
			settings := map[string][]model.Client{}
			json.Unmarshal([]byte(inbound.Settings), &settings)
			clients := settings["clients"]
			for _, c := range clients {
				// Match client by email, or ID, or password based on what's available and matches 'email' (which is clientIdentifier in this context)
				clientIdentifierInLog := email // email from log is the clientIdentifier
				matched := false
				if c.Email != "" && c.Email == clientIdentifierInLog {
					matched = true
				} else if c.ID != "" && c.ID == clientIdentifierInLog { // For vmess/vless if email is used as ID in logs
					matched = true
				} else if c.Password != "" && c.Password == clientIdentifierInLog { // For trojan if email is used as password in logs
					matched = true
				}

				if matched {
					clientData = c
					clientInboundID = inbound.Id // Store the inbound ID
					foundClient = true
					break
				}
			}
			if foundClient {
				break
			}
		}

		if !foundClient {
			logger.Warningf("Client with identifier %s not found for IP processing", email)
			continue
		}

		currentLoggedIps := make([]string, 0, len(uniqueIps))
		for ip := range uniqueIps {
			currentLoggedIps = append(currentLoggedIps, ip)
		}
		sort.Strings(currentLoggedIps)

		// 获取当前客户端的设备指纹
		currentFingerprints := make([]*DeviceFingerprint, 0)
		if clientFingerprints, exists := inboundClientFingerprints[email]; exists {
			for _, fingerprint := range clientFingerprints {
				currentFingerprints = append(currentFingerprints, fingerprint)
			}
		}

		clientIpsRecord, err := j.getInboundClientIps(email) // This function likely needs to be adapted or clientData used directly

		activeIPs := []string{}
		if clientData.ActiveIPs != "" {
			errUnmarshal := json.Unmarshal([]byte(clientData.ActiveIPs), &activeIPs)
			if errUnmarshal != nil {
				logger.Warningf("Error unmarshalling ActiveIPs for client %s: %v", email, errUnmarshal)
				activeIPs = []string{} // Reset if unmarshalling fails
			}
		}

		newActiveIPs := make([]string, len(activeIPs))
		copy(newActiveIPs, activeIPs)
		changedActiveIPs := false

		// 根据指纹模式处理设备限制
		if clientData.MaxDevices > 0 {
			switch clientData.FingerprintMode {
			case "fingerprint":
				// 基于设备指纹的限制
				if len(currentFingerprints) > clientData.MaxDevices {
					// 超出设备限制，封禁多余设备的所有IP
					for i := clientData.MaxDevices; i < len(currentFingerprints); i++ {
						for _, ip := range currentFingerprints[i].IPAddresses {
							if !j.contains(j.disAllowedIps, ip) {
								j.disAllowedIps = append(j.disAllowedIps, ip)
								logger.Infof("[MaxDevices-Fingerprint] IP %s for client %s banned due to exceeding max device limit (%d)", ip, email, clientData.MaxDevices)
								shouldCleanLog = true
							}
						}
					}
				}
			case "hybrid":
				// 混合模式：优先使用指纹，回退到IP
				if len(currentFingerprints) > 0 {
					if len(currentFingerprints) > clientData.MaxDevices {
						for i := clientData.MaxDevices; i < len(currentFingerprints); i++ {
							for _, ip := range currentFingerprints[i].IPAddresses {
								if !j.contains(j.disAllowedIps, ip) {
									j.disAllowedIps = append(j.disAllowedIps, ip)
									logger.Infof("[MaxDevices-Hybrid] IP %s for client %s banned due to exceeding max device limit (%d)", ip, email, clientData.MaxDevices)
									shouldCleanLog = true
								}
							}
						}
					} else {
						// 回退到IP模式
						for _, loggedIp := range currentLoggedIps {
							isExistingActiveIP := j.contains(newActiveIPs, loggedIp)
							if !isExistingActiveIP {
								if len(newActiveIPs) < clientData.MaxDevices {
									newActiveIPs = append(newActiveIPs, loggedIp)
									changedActiveIPs = true
								} else {
									if !j.contains(j.disAllowedIps, loggedIp) {
										j.disAllowedIps = append(j.disAllowedIps, loggedIp)
										logger.Infof("[MaxDevices-Hybrid-IP] IP %s for client %s banned due to exceeding max device limit (%d)", loggedIp, email, clientData.MaxDevices)
										shouldCleanLog = true
									}
								}
							}
						}
					}
				}
			default:
				// 默认IP模式（保持原有逻辑）
				for _, loggedIp := range currentLoggedIps {
					isExistingActiveIP := j.contains(newActiveIPs, loggedIp)
					if !isExistingActiveIP {
						if len(newActiveIPs) < clientData.MaxDevices {
							newActiveIPs = append(newActiveIPs, loggedIp)
							changedActiveIPs = true
						} else {
							if !j.contains(j.disAllowedIps, loggedIp) {
								j.disAllowedIps = append(j.disAllowedIps, loggedIp)
								logger.Infof("[MaxDevices] IP %s for client %s banned due to exceeding max device limit (%d)", loggedIp, email, clientData.MaxDevices)
								shouldCleanLog = true
							}
						}
					}
				}
			}
		}

		if changedActiveIPs {
			activeIPsBytes, marshalErr := json.Marshal(newActiveIPs)
			if marshalErr != nil {
				logger.Warningf("Error marshalling new ActiveIPs for client %s: %v", email, marshalErr)
			} else {
				// Update clientData.ActiveIPs in the database
				// This part is complex because clientData is part of a JSON string in Inbound.Settings
				// A proper solution would involve updating the specific client within the Inbound's settings JSON
				// and then saving the Inbound object.
				// For simplicity, we'll log it. A full implementation needs to update the DB.
				logger.Infof("Client %s ActiveIPs updated to: %s", email, string(activeIPsBytes))
				// Placeholder for actual DB update logic for clientData.ActiveIPs
				// Example: err := s.updateClientActiveIPsInDB(inbound.Id, clientData.ID_or_Email, string(activeIPsBytes)); if err != nil { ... }
				inboundService := service.InboundService{} // Create an instance of InboundService
				dbUpdateErr := inboundService.UpdateClientActiveIPsInDB(clientInboundID, email, string(activeIPsBytes))
				if dbUpdateErr != nil {
					logger.Warningf("Failed to update ActiveIPs in DB for client %s: %v", email, dbUpdateErr)
				}
			}
		}

		// 更新设备指纹数据到数据库
		if len(currentFingerprints) > 0 {
			err := j.updateClientDeviceFingerprints(clientInboundID, email, currentFingerprints)
			if err != nil {
				logger.Warningf("Failed to update device fingerprints for client %s: %v", email, err)
			}
		}

		if err != nil { // This 'err' is from j.getInboundClientIps(email)
			j.addInboundClientIps(email, currentLoggedIps) // This function likely needs to be adapted
			continue
		}

		// Original LimitIP logic (needs to be integrated with new ActiveIPs logic if LimitIP is also active)
		shouldCleanLog = j.updateInboundClientIps(clientIpsRecord, email, currentLoggedIps) || shouldCleanLog
	}

	return shouldCleanLog
}

func (j *CheckClientIpJob) checkFail2BanInstalled() bool {
	cmd := "fail2ban-client"
	args := []string{"-h"}
	err := exec.Command(cmd, args...).Run()
	return err == nil
}

func (j *CheckClientIpJob) checkAccessLogAvailable(iplimitActive bool) bool {
	accessLogPath, err := xray.GetAccessLogPath()
	if err != nil {
		return false
	}

	if accessLogPath == "none" || accessLogPath == "" {
		if iplimitActive {
			logger.Warning("[LimitIP/MaxDevices] Access log path is not set, Please configure the access log path in Xray configs.") // Updated log message
		}
		return false
	}

	return true
}

func (j *CheckClientIpJob) checkError(e error) {
	if e != nil {
		logger.Warning("client ip job err:", e)
	}
}

func (j *CheckClientIpJob) contains(s []string, str string) bool {
	return slices.Contains(s, str)
}

// generateDeviceFingerprint 生成设备指纹ID
func (j *CheckClientIpJob) generateDeviceFingerprint(userAgent, tlsFingerprint string) string {
	if userAgent == "" && tlsFingerprint == "" {
		return ""
	}
	
	// 组合User-Agent和TLS指纹
	combined := fmt.Sprintf("%s|%s", userAgent, tlsFingerprint)
	
	// 生成SHA-256哈希
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// updateClientDeviceFingerprints 更新客户端设备指纹到数据库
func (j *CheckClientIpJob) updateClientDeviceFingerprints(clientInboundID int, email string, fingerprints []*DeviceFingerprint) error {
	if len(fingerprints) == 0 {
		return nil
	}
	
	// 序列化设备指纹数据
	fingerprintsBytes, err := json.Marshal(fingerprints)
	if err != nil {
		return fmt.Errorf("failed to marshal device fingerprints: %v", err)
	}
	
	// 更新数据库
	inboundService := service.InboundService{}
	err = inboundService.UpdateClientDeviceFingerprintsInDB(clientInboundID, email, string(fingerprintsBytes))
	if err != nil {
		return fmt.Errorf("failed to update device fingerprints in DB: %v", err)
	}
	
	logger.Infof("Client %s device fingerprints updated: %d devices", email, len(fingerprints))
	return nil
}

// normalizeUserAgent 标准化User-Agent字符串
func (j *CheckClientIpJob) normalizeUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	
	// 转换为小写并去除多余空格
	normalized := strings.ToLower(strings.TrimSpace(userAgent))
	
	// 移除版本号中的具体数字，保留主要特征
	// 例如：Chrome/91.0.4472.124 -> Chrome/91.x.x.x
	versionRegex := regexp.MustCompile(`(\d+\.)(\d+\.)+(\d+)`)
	normalized = versionRegex.ReplaceAllStringFunc(normalized, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) > 1 {
			return parts[0] + ".x.x.x"
		}
		return match
	})
	
	return normalized
}

func (j *CheckClientIpJob) getInboundClientIps(clientEmail string) (*model.InboundClientIps, error) {
	db := database.GetDB()
	InboundClientIps := &model.InboundClientIps{}
	err := db.Model(model.InboundClientIps{}).Where("client_email = ?", clientEmail).First(InboundClientIps).Error
	if err != nil {
		return nil, err
	}
	return InboundClientIps, nil
}

func (j *CheckClientIpJob) addInboundClientIps(clientEmail string, ips []string) error {
	inboundClientIps := &model.InboundClientIps{}
	jsonIps, err := json.Marshal(ips)
	j.checkError(err)

	inboundClientIps.ClientEmail = clientEmail
	inboundClientIps.Ips = string(jsonIps)

	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	err = tx.Save(inboundClientIps).Error
	if err != nil {
		return err
	}
	return nil
}

func (j *CheckClientIpJob) updateInboundClientIps(inboundClientIps *model.InboundClientIps, clientEmail string, ips []string) bool {
	jsonIps, err := json.Marshal(ips)
	if err != nil {
		logger.Error("failed to marshal IPs to JSON:", err)
		return false
	}

	inboundClientIps.ClientEmail = clientEmail
	inboundClientIps.Ips = string(jsonIps)

	inbound, err := j.getInboundByEmail(clientEmail)
	if err != nil {
		logger.Errorf("failed to fetch inbound settings for email %s: %s", clientEmail, err)
		return false
	}

	if inbound.Settings == "" {
		logger.Debug("wrong data:", inbound)
		return false
	}

	settings := map[string][]model.Client{}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	clients := settings["clients"]
	shouldCleanLog := false
	j.disAllowedIps = []string{}

	logIpFile, err := os.OpenFile(xray.GetIPLimitLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Errorf("failed to open IP limit log file: %s", err)
		return false
	}
	defer logIpFile.Close()
	log.SetOutput(logIpFile)
	log.SetFlags(log.LstdFlags)

	for _, client := range clients {
		if client.Email == clientEmail {
			limitIp := client.LimitIP

			if limitIp > 0 && inbound.Enable {
				shouldCleanLog = true

				if limitIp < len(ips) {
					j.disAllowedIps = append(j.disAllowedIps, ips[limitIp:]...)
					for i := limitIp; i < len(ips); i++ {
						log.Printf("[LIMIT_IP] Email = %s || SRC = %s", clientEmail, ips[i])
					}
				}
			}
		}
	}

	sort.Strings(j.disAllowedIps)

	if len(j.disAllowedIps) > 0 {
		logger.Debug("disAllowedIps:", j.disAllowedIps)
	}

	db := database.GetDB()
	err = db.Save(inboundClientIps).Error
	if err != nil {
		logger.Error("failed to save inboundClientIps:", err)
		return false
	}

	return shouldCleanLog
}

func (j *CheckClientIpJob) getInboundByEmail(clientEmail string) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}

	err := db.Model(&model.Inbound{}).Where("settings LIKE ?", "%"+clientEmail+"%").First(inbound).Error
	if err != nil {
		return nil, err
	}

	return inbound, nil
}
