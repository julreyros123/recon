from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class DeviceBase(BaseModel):
    ip: str = Field(..., description="IP Address of the device")
    mac: Optional[str] = Field(None, description="MAC Address of the device")
    hostname: Optional[str] = Field(None, description="Hostname/Name of the device")
    vendor: Optional[str] = Field(None, description="Device manufacturer/vendor")
    status: str = Field("unknown", description="Status of the device (active, inactive, unknown)")
    open_ports: Optional[str] = Field(None, description="JSON array of open ports on the device")
    os_type: Optional[str] = Field("generic", description="Device type classification (e.g. router, workstation, server)")
    is_trusted: bool = Field(False, description="Whether the device is trusted by the administrator")
    owner_name: Optional[str] = Field(None, description="Owner of the device")
    department: Optional[str] = Field(None, description="Department of the owner")
    purpose: Optional[str] = Field(None, description="Purpose or description of use")
    trust_level: str = Field("Unknown", description="Trust level: Trusted, Pending, Blocked, Unknown")
    registered_by: Optional[str] = Field(None, description="Operator who registered the device")
    date_registered: Optional[datetime] = Field(None, description="Timestamp when registered")
    # --- Extended hardware & identity ---
    serial_number: Optional[str] = Field(None, description="Device serial number")
    model: Optional[str] = Field(None, description="Device model name")
    firmware_version: Optional[str] = Field(None, description="Currently running firmware/OS version")
    latest_firmware: Optional[str] = Field(None, description="Latest available vendor firmware version")
    firmware_eol: Optional[bool] = Field(False, description="True if firmware/OS is End-of-Life")
    warranty_expiry: Optional[str] = Field(None, description="Warranty expiry date (ISO date string, e.g. 2027-12-31)")
    purchase_date: Optional[str] = Field(None, description="Device acquisition date (ISO date string)")
    # --- Network topology ---
    vlan: Optional[str] = Field(None, description="VLAN tag/ID (e.g. VLAN-10)")
    switch_port: Optional[str] = Field(None, description="Physical switch port (e.g. Gi0/1)")
    site_location: Optional[str] = Field(None, description="Physical site location (e.g. Building A - Floor 2)")
    rack_position: Optional[str] = Field(None, description="Rack and slot position (e.g. Rack-02 U14)")
    admin_contact: Optional[str] = Field(None, description="Primary technical/admin contact")
    # --- Security controls ---
    ssh_enabled: Optional[bool] = Field(False, description="SSH management protocol active")
    telnet_enabled: Optional[bool] = Field(False, description="Telnet (insecure) management active")
    snmp_enabled: Optional[bool] = Field(False, description="SNMP active on device")
    http_mgmt_enabled: Optional[bool] = Field(False, description="HTTP management interface active")
    mfa_enforced: Optional[bool] = Field(False, description="MFA enforcement status")
    local_users: Optional[str] = Field(None, description="JSON array of local user accounts on the device")
    # --- OS tracking ---
    baseline_os: Optional[str] = Field(None, description="OS recorded at time of first registration (locked baseline)")
    current_os: Optional[str] = Field(None, description="OS/firmware detected by the most recent scan")

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    status: Optional[str] = None
    open_ports: Optional[str] = None
    os_type: Optional[str] = None
    is_trusted: Optional[bool] = None
    owner_name: Optional[str] = None
    department: Optional[str] = None
    purpose: Optional[str] = None
    trust_level: Optional[str] = None
    registered_by: Optional[str] = None
    date_registered: Optional[datetime] = None
    # --- Extended hardware & identity ---
    serial_number: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    latest_firmware: Optional[str] = None
    firmware_eol: Optional[bool] = None
    warranty_expiry: Optional[str] = None
    purchase_date: Optional[str] = None
    # --- Network topology ---
    vlan: Optional[str] = None
    switch_port: Optional[str] = None
    site_location: Optional[str] = None
    rack_position: Optional[str] = None
    admin_contact: Optional[str] = None
    # --- Security controls ---
    ssh_enabled: Optional[bool] = None
    telnet_enabled: Optional[bool] = None
    snmp_enabled: Optional[bool] = None
    http_mgmt_enabled: Optional[bool] = None
    mfa_enforced: Optional[bool] = None
    local_users: Optional[str] = None
    # --- OS tracking ---
    baseline_os: Optional[str] = None
    current_os: Optional[str] = None


class Device(DeviceBase):
    id: int
    last_seen: datetime

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "staff"
    is_active: bool = True
    allowed_ip: str = "*"

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int
    login_attempts: Optional[int] = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class ScanReport(BaseModel):
    id: int
    timestamp: datetime
    devices_found: int
    active_devices: int
    scan_duration_secs: float
    summary: Optional[str] = None

class AuditLogBase(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    action: str
    target: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[str] = None

class AuditLog(AuditLogBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True
