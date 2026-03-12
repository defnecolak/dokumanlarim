const { randomUUID } = require('crypto');
const { readDB, withDB } = require('./db');

/**
 * Ensure notifications array exists in the database
 */
function ensureNotificationsArray(db) {
  if (!Array.isArray(db.notifications)) {
    db.notifications = [];
  }
  return db.notifications;
}

/**
 * Add a notification to the database
 * @param {Object} options
 * @param {string} options.tenantId - Tenant ID
 * @param {string} options.userId - Target user ID (null for all tenant users)
 * @param {string} options.type - Notification type
 * @param {string} options.title - Notification title
 * @param {string} options.message - Notification message
 * @param {string} options.link - Relative URL to navigate to
 * @returns {Object} The created notification
 */
function addNotification({ tenantId, userId, type, title, message, link }) {
  const notification = {
    id: randomUUID(),
    tenantId,
    userId: userId || null,
    type,
    title,
    message,
    link,
    read: false,
    createdAt: new Date().toISOString(),
  };

  withDB((db) => {
    ensureNotificationsArray(db);
    db.notifications.push(notification);
  });

  return notification;
}

/**
 * Get the count of unread notifications for a user
 * @param {string} tenantId - Tenant ID
 * @param {string} userId - User ID
 * @returns {number} Count of unread notifications
 */
function getUnreadCount(tenantId, userId) {
  const db = readDB();
  const notifications = ensureNotificationsArray(db);

  return notifications.filter(
    (n) =>
      n.tenantId === tenantId &&
      (n.userId === userId || n.userId === null) &&
      !n.read
  ).length;
}

/**
 * Get notifications for a user with filtering and pagination
 * @param {string} tenantId - Tenant ID
 * @param {string} userId - User ID
 * @param {Object} options
 * @param {number} options.limit - Max number of results (default: 50)
 * @param {number} options.offset - Skip this many results (default: 0)
 * @param {boolean} options.unreadOnly - Return only unread notifications (default: false)
 * @returns {Array} Notifications array sorted by newest first
 */
function getNotifications(tenantId, userId, { limit = 50, offset = 0, unreadOnly = false } = {}) {
  const db = readDB();
  const notifications = ensureNotificationsArray(db);

  let filtered = notifications.filter(
    (n) =>
      n.tenantId === tenantId &&
      (n.userId === userId || n.userId === null)
  );

  if (unreadOnly) {
    filtered = filtered.filter((n) => !n.read);
  }

  // Sort by newest first
  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  // Apply pagination
  return filtered.slice(offset, offset + limit);
}

/**
 * Mark a single notification as read
 * @param {string} notificationId - Notification ID
 * @returns {boolean} True if notification was found and updated, false otherwise
 */
function markAsRead(notificationId) {
  return withDB((db) => {
    const notifications = ensureNotificationsArray(db);
    const notification = notifications.find((n) => n.id === notificationId);

    if (!notification) {
      return false;
    }

    notification.read = true;
    return true;
  });
}

/**
 * Mark all notifications as read for a user
 * @param {string} tenantId - Tenant ID
 * @param {string} userId - User ID
 * @returns {number} Number of notifications marked as read
 */
function markAllAsRead(tenantId, userId) {
  return withDB((db) => {
    const notifications = ensureNotificationsArray(db);
    let count = 0;

    notifications.forEach((n) => {
      if (
        n.tenantId === tenantId &&
        (n.userId === userId || n.userId === null) &&
        !n.read
      ) {
        n.read = true;
        count++;
      }
    });

    return count;
  });
}

/**
 * Delete notifications older than X days for a tenant
 * @param {string} tenantId - Tenant ID
 * @param {number} daysOld - Delete notifications older than this many days
 * @returns {number} Number of notifications deleted
 */
function deleteOldNotifications(tenantId, daysOld) {
  return withDB((db) => {
    const notifications = ensureNotificationsArray(db);
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const initialLength = notifications.length;

    // Keep only notifications that are either:
    // 1. From a different tenant, OR
    // 2. From this tenant but newer than cutoffDate
    db.notifications = notifications.filter(
      (n) =>
        n.tenantId !== tenantId ||
        new Date(n.createdAt) >= cutoffDate
    );

    return initialLength - db.notifications.length;
  });
}

module.exports = {
  addNotification,
  getUnreadCount,
  getNotifications,
  markAsRead,
  markAllAsRead,
  deleteOldNotifications,
};
