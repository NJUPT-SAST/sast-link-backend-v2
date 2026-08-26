package sessionhandler

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

type deviceDTO struct {
	DeviceID  string    `json:"device_id"`
	UA        string    `json:"ua"`
	IP        string    `json:"ip"`
	LoginTime time.Time `json:"login_time"`
	LastSeen  time.Time `json:"last_seen"`
}

type listDevicesResponse struct {
	Devices []deviceDTO `json:"devices"`
}

type logoutDeviceResponse struct {
	Message string `json:"message"`
}

// ListDevices returns the caller's logged-in devices, newest login first. The
// device ID is the token family ID; the service answers an empty list when the
// device store is unavailable (fail-open, PRD §6.1), so this endpoint is a view
// that degrades, never a blocker.
func (h Handler) ListDevices(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	result, err := h.Service.ListDevices(c.Request.Context(), session.ListDevicesInput{
		UserID: principal.UserID,
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	devices := make([]deviceDTO, 0, len(result.Devices))
	for _, device := range result.Devices {
		devices = append(devices, deviceDTO{
			DeviceID:  device.DeviceID,
			UA:        device.UA,
			IP:        device.IP,
			LoginTime: device.LoginTime,
			LastSeen:  device.LastSeen,
		})
	}
	response.Ok(c, listDevicesResponse{Devices: devices})
}

// LogoutDevice revokes one device's whole token family and drops its device
// record. The device ID is an opaque UUID (the family ID), so a string that
// does not name a device of the caller answers 40400 rather than 400 — the
// error never confirms whether someone else's device exists. The parameter is
// trimmed first so an encoded blank (%20) takes the same 40400 path as a
// missing one.
func (h Handler) LogoutDevice(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		response.Error(c, internalError())
		return
	}
	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		response.Error(c, notFound(errcode.CodeNotFound, "设备不存在"))
		return
	}
	if _, err := h.Service.LogoutDevice(c.Request.Context(), session.LogoutDeviceInput{
		UserID:        principal.UserID,
		DeviceID:      deviceID,
		ActorClientID: principal.ClientID,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
	}); err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	response.Ok(c, logoutDeviceResponse{Message: "该设备已登出"})
}
