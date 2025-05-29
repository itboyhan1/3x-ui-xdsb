package model

import (
	"x-ui/xray"
)

type Protocol string

const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	DOKODEMO    Protocol = "dokodemo-door"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Socks       Protocol = "socks"
	WireGuard   Protocol = "wireguard"
)

type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Id          int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId      int                  `json:"-"`
	Up          int64                `json:"up" form:"up"`
	Down        int64                `json:"down" form:"down"`
	Total       int64                `json:"total" form:"total"`
	Remark      string               `json:"remark" form:"remark"`
	Enable      bool                 `json:"enable" form:"enable"`
	ExpiryTime  int64                `json:"expiryTime" form:"expiryTime"`
	ClientStats []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
	Allocate       string   `json:"allocate" form:"allocate"`
}

type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

// GenXrayInboundConfig method moved to avoid circular import
// This method should be implemented in a service layer instead

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type Client struct {
	ID         string `json:"id"`
	Security   string `json:"security"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB" form:"totalGB"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`
	Enable     bool   `json:"enable" form:"enable"`
	TgID       int64  `json:"tgId" form:"tgId"`
	SubID      string `json:"subId" form:"subId"`
	Comment    string `json:"comment" form:"comment"`
	Reset      int    `json:"reset" form:"reset"`
	MaxDevices int    `json:"maxDevices" form:"maxDevices" gorm:"default:0"` // 新增：最大设备数量限制, 0表示不限制
	ActiveIPs  string `json:"activeIPs" form:"activeIPs" gorm:"type:text"`   // 新增：当前活动的IP列表 (JSON字符串)
	DeviceFingerprints string `json:"deviceFingerprints" form:"deviceFingerprints" gorm:"type:text"` // 设备指纹信息 (JSON字符串)
	FingerprintMode    string `json:"fingerprintMode" form:"fingerprintMode" gorm:"default:ip"`     // 识别模式：ip/fingerprint/hybrid
}
