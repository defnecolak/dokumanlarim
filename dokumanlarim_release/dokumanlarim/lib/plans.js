const PLANS = {
  free: {
    code: 'free',
    label: 'Ücretsiz',
    priceLabel: '0₺',
    maxUsers: 1,
    maxActiveRequests: 3,
    maxDocsPerRequest: 10,
    retentionDays: 30,
    features: ['Temel portal', 'ZIP indir', 'CSV dışa aktarım'],
  },
  starter: {
    code: 'starter',
    label: 'Başlangıç',
    priceLabel: '29$/ay',
    maxUsers: 3,
    maxActiveRequests: 25,
    maxDocsPerRequest: 30,
    retentionDays: 90,
    features: ['E-posta daveti (vendor)', 'Hatırlatma e-postası', 'Ekip daveti (3 kullanıcı)'],
  },
  team: {
    code: 'team',
    label: 'Takım',
    priceLabel: '79$/ay',
    maxUsers: 10,
    maxActiveRequests: 200,
    maxDocsPerRequest: 60,
    retentionDays: 365,
    features: ['Takım kullanımı', 'Ekip daveti (10 kullanıcı)', 'Gelişmiş raporlar (yakında)'],
  },
  pro: {
    code: 'pro',
    label: 'Pro',
    priceLabel: '149$/ay',
    maxUsers: 30,
    maxActiveRequests: 1000,
    maxDocsPerRequest: 120,
    retentionDays: 3650,
    features: ['Çoklu ekip', 'Ekip daveti (30 kullanıcı)', 'Öncelikli destek', 'Entegrasyonlar (yakında)'],
  },
};

function getPlanForTenant(db, tenantId) {
  const bills = (db.billing || [])
    .filter(b => b.tenantId === tenantId && b.status === 'active')
    .sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  const code = bills[0]?.plan || 'free';
  return PLANS[code] || PLANS.free;
}

module.exports = { PLANS, getPlanForTenant };
