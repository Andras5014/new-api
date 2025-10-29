package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func GoogleOAuth(c *gin.Context) {
	session := sessions.Default(c)
	state := c.Query("state")
	if state == "" || session.Get("oauth_state") == nil || state != session.Get("oauth_state").(string) {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "state is empty or not same"})
		return
	}

	if username := session.Get("username"); username != nil {
		GoogleBind(c)
		return
	}

	if !common.GoogleOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "管理员未开启通过 Google 登录以及注册"})
		return
	}

	code := c.Query("code")
	googleUser, err := getGoogleUserInfoByCodeNoLib(code)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	user := model.User{GoogleId: googleUser.Sub}

	if model.IsGoogleIdAlreadyTaken(user.GoogleId) {
		if err := user.FillUserByGoogleId(); err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
		if user.Id == 0 {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "用户已注销"})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = "google_" + strconv.Itoa(model.GetMaxUserId()+1)
			if googleUser.Name != "" {
				user.DisplayName = googleUser.Name
			} else {
				user.DisplayName = "Google User"
			}
			user.Email = googleUser.Email
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled

			affCode := session.Get("aff")
			inviterId := 0
			if affCode != nil {
				inviterId, _ = model.GetUserIdByAffCode(affCode.(string))
			}

			if err := user.Insert(inviterId); err != nil {
				c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "管理员关闭了新用户注册"})
			return
		}
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "用户已被封禁"})
		return
	}

	setupLogin(&user, c)
}
func GoogleBind(c *gin.Context) {
	if !common.GoogleOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 Google 登录以及注册",
		})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "code 不能为空",
		})
		return
	}

	// 通过 code 获取 Google 用户信息
	googleUser, err := getGoogleUserInfoByCodeNoLib(code)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	user := model.User{
		GoogleId: googleUser.Sub,
	}

	// 检查是否已经被绑定
	if model.IsGoogleIdAlreadyTaken(user.GoogleId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该 Google 账户已被绑定",
		})
		return
	}

	session := sessions.Default(c)
	id := session.Get("id")
	if id == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录再绑定账户",
		})
		return
	}

	user.Id = id.(int)
	if err := user.FillUserById(); err != nil {
		common.ApiError(c, err)
		return
	}

	user.GoogleId = googleUser.Sub
	if err := user.Update(false); err != nil {
		common.ApiError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Google 账户绑定成功",
	})
}

func getGoogleUserInfoByCodeNoLib(code string) (*googleUserInfo, error) {
	// 1. Exchange code for token
	data := map[string]string{
		"code":          code,
		"client_id":     common.GoogleClientID,
		"client_secret": common.GoogleClientSecret,
		"redirect_uri":  common.GoogleRedirectURL,
		"grant_type":    "authorization_code",
	}
	jsonBody, _ := json.Marshal(data)

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("exchange token failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var token googleTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse token response failed: %w", err)
	}

	req, _ := http.NewRequest("GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get userinfo failed: %w", err)
	}
	defer userResp.Body.Close()

	userBody, _ := io.ReadAll(userResp.Body)
	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s", userResp.StatusCode, string(userBody))
	}

	var user googleUserInfo
	if err := json.Unmarshal(userBody, &user); err != nil {
		return nil, fmt.Errorf("parse userinfo failed: %w", err)
	}

	if user.Sub == "" {
		return nil, fmt.Errorf("missing google user id (sub)")
	}
	return &user, nil
}
