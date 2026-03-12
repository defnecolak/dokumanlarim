/**
 * i18n - Internationalization Module
 * Supports Turkish (tr) and English (en) languages
 * For Dökümanlarım Document Management SaaS
 */

// Dictionary with all UI strings in Turkish and English
const DICTIONARY = {
  nav: {
    home: {
      tr: 'Ana Sayfa',
      en: 'Home'
    },
    requests: {
      tr: 'İstekler',
      en: 'Requests'
    },
    newRequest: {
      tr: 'Yeni İstek',
      en: 'New Request'
    },
    team: {
      tr: 'Ekip',
      en: 'Team'
    },
    templates: {
      tr: 'Şablonlar',
      en: 'Templates'
    },
    billing: {
      tr: 'Faturalandırma',
      en: 'Billing'
    },
    settings: {
      tr: 'Ayarlar',
      en: 'Settings'
    },
    logout: {
      tr: 'Çıkış Yap',
      en: 'Logout'
    },
    login: {
      tr: 'Giriş Yap',
      en: 'Login'
    },
    signup: {
      tr: 'Kayıt Ol',
      en: 'Sign Up'
    }
  },
  auth: {
    loginTitle: {
      tr: 'Giriş Yapın',
      en: 'Login'
    },
    signupTitle: {
      tr: 'Kayıt Olun',
      en: 'Create Account'
    },
    email: {
      tr: 'E-posta',
      en: 'Email'
    },
    password: {
      tr: 'Şifre',
      en: 'Password'
    },
    forgotPassword: {
      tr: 'Şifremi Unuttum',
      en: 'Forgot Password?'
    },
    resetPassword: {
      tr: 'Şifreyi Sıfırla',
      en: 'Reset Password'
    },
    mfaTitle: {
      tr: 'İki Faktörlü Doğrulama',
      en: 'Two-Factor Authentication'
    },
    mfaCode: {
      tr: 'Doğrulama Kodu',
      en: 'Verification Code'
    },
    backupCode: {
      tr: 'Yedek Kod',
      en: 'Backup Code'
    }
  },
  requests: {
    title: {
      tr: 'İstekler',
      en: 'Requests'
    },
    new: {
      tr: 'Yeni İstek',
      en: 'New Request'
    },
    vendor: {
      tr: 'Tedarikçi',
      en: 'Vendor'
    },
    company: {
      tr: 'Şirket',
      en: 'Company'
    },
    status: {
      tr: 'Durum',
      en: 'Status'
    },
    progress: {
      tr: 'İlerleme',
      en: 'Progress'
    },
    dueDate: {
      tr: 'Son Tarih',
      en: 'Due Date'
    },
    note: {
      tr: 'Not',
      en: 'Note'
    },
    delete: {
      tr: 'Sil',
      en: 'Delete'
    },
    download: {
      tr: 'İndir',
      en: 'Download'
    },
    downloadAll: {
      tr: 'Tümünü İndir',
      en: 'Download All'
    },
    filter: {
      tr: 'Filtrele',
      en: 'Filter'
    },
    all: {
      tr: 'Tümü',
      en: 'All'
    },
    open: {
      tr: 'Açık',
      en: 'Open'
    },
    submitted: {
      tr: 'Gönderildi',
      en: 'Submitted'
    },
    approved: {
      tr: 'Onaylandı',
      en: 'Approved'
    },
    rejected: {
      tr: 'Reddedildi',
      en: 'Rejected'
    },
    archived: {
      tr: 'Arşivlendi',
      en: 'Archived'
    },
    noRequests: {
      tr: 'İstek bulunamadı',
      en: 'No requests found'
    },
    created: {
      tr: 'Oluşturuldu',
      en: 'Created'
    },
    detail: {
      tr: 'Detay',
      en: 'Detail'
    }
  },
  documents: {
    title: {
      tr: 'Belgeler',
      en: 'Documents'
    },
    required: {
      tr: 'Gerekli',
      en: 'Required'
    },
    optional: {
      tr: 'İsteğe Bağlı',
      en: 'Optional'
    },
    missing: {
      tr: 'Eksik',
      en: 'Missing'
    },
    uploaded: {
      tr: 'Yüklendi',
      en: 'Uploaded'
    },
    expired: {
      tr: 'Süresi Doldu',
      en: 'Expired'
    },
    expiringSoon: {
      tr: 'Yakında Süresi Dolacak',
      en: 'Expiring Soon'
    },
    daysLeft: {
      tr: '{n} gün kaldı',
      en: '{n} days left'
    },
    signature: {
      tr: 'İmza',
      en: 'Signature'
    },
    signed: {
      tr: 'İmzalı',
      en: 'Signed'
    },
    unsigned: {
      tr: 'İmzasız',
      en: 'Unsigned'
    },
    verified: {
      tr: 'Doğrulandı',
      en: 'Verified'
    },
    pending: {
      tr: 'Beklemede',
      en: 'Pending'
    },
    issueDate: {
      tr: 'Düzenleme Tarihi',
      en: 'Issue Date'
    },
    expiryDate: {
      tr: 'Son Geçerlilik Tarihi',
      en: 'Expiry Date'
    },
    download: {
      tr: 'İndir',
      en: 'Download'
    },
    upload: {
      tr: 'Yükle',
      en: 'Upload'
    },
    version: {
      tr: 'Versiyon',
      en: 'Version'
    },
    currentVersion: {
      tr: 'Geçerli Versiyon',
      en: 'Current Version'
    },
    previousVersions: {
      tr: 'Önceki Versiyonlar',
      en: 'Previous Versions'
    },
    approve: {
      tr: 'Onayla',
      en: 'Approve'
    },
    reject: {
      tr: 'Reddet',
      en: 'Reject'
    },
    revise: {
      tr: 'Düzelt',
      en: 'Revise'
    },
    reviewStatus: {
      tr: 'İnceleme Durumu',
      en: 'Review Status'
    }
  },
  team: {
    title: {
      tr: 'Ekip',
      en: 'Team'
    },
    invite: {
      tr: 'Davet Et',
      en: 'Invite'
    },
    members: {
      tr: 'Üyeler',
      en: 'Members'
    },
    role: {
      tr: 'Rol',
      en: 'Role'
    },
    owner: {
      tr: 'Sahibi',
      en: 'Owner'
    },
    member: {
      tr: 'Üye',
      en: 'Member'
    },
    revoke: {
      tr: 'İptal Et',
      en: 'Revoke'
    },
    remove: {
      tr: 'Kaldır',
      en: 'Remove'
    },
    inviteLink: {
      tr: 'Davet Linki',
      en: 'Invite Link'
    },
    pending: {
      tr: 'Beklemede',
      en: 'Pending'
    }
  },
  billing: {
    title: {
      tr: 'Faturalandırma',
      en: 'Billing'
    },
    plan: {
      tr: 'Plan',
      en: 'Plan'
    },
    free: {
      tr: 'Ücretsiz',
      en: 'Free'
    },
    starter: {
      tr: 'Başlangıç',
      en: 'Starter'
    },
    teamPlan: {
      tr: 'Ekip Planı',
      en: 'Team Plan'
    },
    pro: {
      tr: 'Profesyonel',
      en: 'Professional'
    },
    upgrade: {
      tr: 'Yükselt',
      en: 'Upgrade'
    },
    currentPlan: {
      tr: 'Mevcut Plan',
      en: 'Current Plan'
    },
    features: {
      tr: 'Özellikler',
      en: 'Features'
    }
  },
  settings: {
    title: {
      tr: 'Ayarlar',
      en: 'Settings'
    },
    tenantName: {
      tr: 'Kurum Adı',
      en: 'Tenant Name'
    },
    smtp: {
      tr: 'SMTP Ayarları',
      en: 'SMTP Settings'
    },
    webhooks: {
      tr: 'Web Kancaları',
      en: 'Webhooks'
    },
    notifications: {
      tr: 'Bildirimler',
      en: 'Notifications'
    },
    language: {
      tr: 'Dil',
      en: 'Language'
    },
    save: {
      tr: 'Kaydet',
      en: 'Save'
    }
  },
  security: {
    title: {
      tr: 'Güvenlik',
      en: 'Security'
    },
    mfa: {
      tr: 'İki Faktörlü Doğrulama',
      en: 'Two-Factor Authentication'
    },
    enable: {
      tr: 'Etkinleştir',
      en: 'Enable'
    },
    disable: {
      tr: 'Devre Dışı Bırak',
      en: 'Disable'
    },
    backupCodes: {
      tr: 'Yedek Kodlar',
      en: 'Backup Codes'
    },
    password: {
      tr: 'Şifre',
      en: 'Password'
    },
    changePassword: {
      tr: 'Şifreyi Değiştir',
      en: 'Change Password'
    },
    newPassword: {
      tr: 'Yeni Şifre',
      en: 'New Password'
    },
    confirmPassword: {
      tr: 'Şifreyi Onayla',
      en: 'Confirm Password'
    }
  },
  dashboard: {
    title: {
      tr: 'Kontrol Paneli',
      en: 'Dashboard'
    },
    overview: {
      tr: 'Genel Bakış',
      en: 'Overview'
    },
    activeRequests: {
      tr: 'Aktif İstekler',
      en: 'Active Requests'
    },
    pendingDocs: {
      tr: 'Bekleyen Belgeler',
      en: 'Pending Documents'
    },
    expiringSoon: {
      tr: 'Yakında Süresi Dolacak',
      en: 'Expiring Soon'
    },
    completionRate: {
      tr: 'Tamamlanma Oranı',
      en: 'Completion Rate'
    },
    recentActivity: {
      tr: 'Son Aktivite',
      en: 'Recent Activity'
    },
    vendorCompliance: {
      tr: 'Tedarikçi Uyumu',
      en: 'Vendor Compliance'
    },
    avgCompletionTime: {
      tr: 'Ortalama Tamamlanma Süresi',
      en: 'Average Completion Time'
    },
    totalRequests: {
      tr: 'Toplam İstekler',
      en: 'Total Requests'
    },
    totalVendors: {
      tr: 'Toplam Tedarikçi',
      en: 'Total Vendors'
    }
  },
  notifications: {
    title: {
      tr: 'Bildirimler',
      en: 'Notifications'
    },
    markRead: {
      tr: 'Okundu Olarak İşaretle',
      en: 'Mark as Read'
    },
    markAllRead: {
      tr: 'Tümünü Okundu Olarak İşaretle',
      en: 'Mark All as Read'
    },
    noNotifications: {
      tr: 'Bildirim yok',
      en: 'No notifications'
    },
    newUpload: {
      tr: 'Yeni Yükleme',
      en: 'New Upload'
    },
    docExpiring: {
      tr: 'Belge Süresi Dolmak Üzere',
      en: 'Document Expiring'
    },
    requestSubmitted: {
      tr: 'İstek Gönderildi',
      en: 'Request Submitted'
    },
    requestApproved: {
      tr: 'İstek Onaylandı',
      en: 'Request Approved'
    },
    requestRejected: {
      tr: 'İstek Reddedildi',
      en: 'Request Rejected'
    },
    docRevisionRequested: {
      tr: 'Belge Revizyonu İstendi',
      en: 'Document Revision Requested'
    }
  },
  reports: {
    title: {
      tr: 'Raporlar',
      en: 'Reports'
    },
    monthly: {
      tr: 'Aylık',
      en: 'Monthly'
    },
    compliance: {
      tr: 'Uyum',
      en: 'Compliance'
    },
    completionTime: {
      tr: 'Tamamlanma Süresi',
      en: 'Completion Time'
    },
    vendorPerformance: {
      tr: 'Tedarikçi Performansı',
      en: 'Vendor Performance'
    },
    exportCsv: {
      tr: 'CSV olarak dışa aktar',
      en: 'Export as CSV'
    },
    exportPdf: {
      tr: 'PDF olarak dışa aktar',
      en: 'Export as PDF'
    },
    dateRange: {
      tr: 'Tarih Aralığı',
      en: 'Date Range'
    },
    generate: {
      tr: 'Oluştur',
      en: 'Generate'
    }
  },
  common: {
    save: {
      tr: 'Kaydet',
      en: 'Save'
    },
    cancel: {
      tr: 'İptal',
      en: 'Cancel'
    },
    delete: {
      tr: 'Sil',
      en: 'Delete'
    },
    edit: {
      tr: 'Düzenle',
      en: 'Edit'
    },
    create: {
      tr: 'Oluştur',
      en: 'Create'
    },
    back: {
      tr: 'Geri',
      en: 'Back'
    },
    next: {
      tr: 'İleri',
      en: 'Next'
    },
    previous: {
      tr: 'Önceki',
      en: 'Previous'
    },
    search: {
      tr: 'Ara',
      en: 'Search'
    },
    filter: {
      tr: 'Filtrele',
      en: 'Filter'
    },
    yes: {
      tr: 'Evet',
      en: 'Yes'
    },
    no: {
      tr: 'Hayır',
      en: 'No'
    },
    confirm: {
      tr: 'Onayla',
      en: 'Confirm'
    },
    loading: {
      tr: 'Yükleniyor...',
      en: 'Loading...'
    },
    noData: {
      tr: 'Veri bulunamadı',
      en: 'No data found'
    },
    actions: {
      tr: 'İşlemler',
      en: 'Actions'
    },
    date: {
      tr: 'Tarih',
      en: 'Date'
    },
    time: {
      tr: 'Saat',
      en: 'Time'
    },
    all: {
      tr: 'Tümü',
      en: 'All'
    },
    none: {
      tr: 'Hiçbiri',
      en: 'None'
    },
    selectAll: {
      tr: 'Tümünü Seç',
      en: 'Select All'
    },
    deselectAll: {
      tr: 'Tümünün Seçimini Kaldır',
      en: 'Deselect All'
    },
    bulkActions: {
      tr: 'Toplu İşlemler',
      en: 'Bulk Actions'
    },
    send: {
      tr: 'Gönder',
      en: 'Send'
    },
    refresh: {
      tr: 'Yenile',
      en: 'Refresh'
    }
  },
  statuses: {
    draft: {
      tr: 'Taslak',
      en: 'Draft'
    },
    open: {
      tr: 'Açık',
      en: 'Open'
    },
    submitted: {
      tr: 'Gönderildi',
      en: 'Submitted'
    },
    approved: {
      tr: 'Onaylandı',
      en: 'Approved'
    },
    rejected: {
      tr: 'Reddedildi',
      en: 'Rejected'
    },
    archived: {
      tr: 'Arşivlendi',
      en: 'Archived'
    },
    completed: {
      tr: 'Tamamlandı',
      en: 'Completed'
    },
    pending: {
      tr: 'Beklemede',
      en: 'Pending'
    },
    inReview: {
      tr: 'İnceleme Altında',
      en: 'In Review'
    }
  },
  errors: {
    required: {
      tr: 'Bu alan gereklidir',
      en: 'This field is required'
    },
    invalidEmail: {
      tr: 'Geçersiz e-posta adresi',
      en: 'Invalid email address'
    },
    tooShort: {
      tr: 'Çok kısa',
      en: 'Too short'
    },
    tooLong: {
      tr: 'Çok uzun',
      en: 'Too long'
    },
    notFound: {
      tr: 'Bulunamadı',
      en: 'Not found'
    },
    unauthorized: {
      tr: 'Yetkisiz erişim',
      en: 'Unauthorized'
    },
    forbidden: {
      tr: 'Erişim reddedildi',
      en: 'Forbidden'
    },
    serverError: {
      tr: 'Sunucu hatası',
      en: 'Server error'
    },
    networkError: {
      tr: 'Ağ hatası',
      en: 'Network error'
    }
  }
};

/**
 * Translate a key with optional parameter interpolation
 * @param {string} lang - Language code ('tr' or 'en')
 * @param {string} key - Translation key in format 'category.key' (e.g., 'requests.count')
 * @param {Object} params - Optional parameters for interpolation
 * @returns {string} Translated string with interpolated parameters
 */
function t(lang, key, params = {}) {
  // Validate language
  if (!['tr', 'en'].includes(lang)) {
    lang = 'tr'; // Fallback to Turkish
  }

  // Split key into category and property
  const [category, ...keyParts] = key.split('.');
  const property = keyParts.join('.');

  // Navigate to the translation
  if (!DICTIONARY[category] || !DICTIONARY[category][property]) {
    console.warn(`Translation key not found: ${key}`);
    return key; // Return key as fallback
  }

  let translation = DICTIONARY[category][property][lang];

  // Handle missing language translation
  if (!translation) {
    translation = DICTIONARY[category][property]['tr']; // Fallback to Turkish
  }

  // Interpolate parameters
  if (Object.keys(params).length > 0) {
    Object.keys(params).forEach(paramKey => {
      const regex = new RegExp(`\\{${paramKey}\\}`, 'g');
      translation = translation.replace(regex, params[paramKey]);
    });
  }

  return translation;
}

/**
 * Get locale from request
 * Priority: req.session.lang → req.query.lang → Accept-Language header → 'tr' (default)
 * @param {Object} req - Express request object
 * @returns {string} Language code ('tr' or 'en')
 */
function getLocale(req) {
  // Check session
  if (req.session && req.session.lang) {
    const sessionLang = req.session.lang;
    if (['tr', 'en'].includes(sessionLang)) {
      return sessionLang;
    }
  }

  // Check query parameter
  if (req.query && req.query.lang) {
    const queryLang = req.query.lang;
    if (['tr', 'en'].includes(queryLang)) {
      return queryLang;
    }
  }

  // Check Accept-Language header
  if (req.headers && req.headers['accept-language']) {
    const acceptLanguage = req.headers['accept-language'];

    // Parse first language preference
    const languages = acceptLanguage.split(',')[0].split('-')[0].toLowerCase();

    if (languages === 'en') {
      return 'en';
    }

    if (languages === 'tr') {
      return 'tr';
    }
  }

  // Default to Turkish
  return 'tr';
}

/**
 * Supported languages
 */
const LANGUAGES = [
  {
    code: 'tr',
    label: 'Türkçe'
  },
  {
    code: 'en',
    label: 'English'
  }
];

// Export functions and constants
module.exports = {
  t,
  getLocale,
  LANGUAGES,
  DICTIONARY
};
