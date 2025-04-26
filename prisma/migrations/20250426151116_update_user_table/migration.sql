-- AlterTable
ALTER TABLE `User` ADD COLUMN `appMetadata` JSON NULL,
    ADD COLUMN `forcePasswordChange` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `lockExpiresAt` DATETIME(3) NULL,
    ADD COLUMN `lockedAt` DATETIME(3) NULL,
    ADD COLUMN `pendingPhone` VARCHAR(20) NULL,
    ADD COLUMN `phone` VARCHAR(20) NULL,
    ADD COLUMN `phoneVerificationCode` VARCHAR(6) NULL,
    ADD COLUMN `phoneVerificationSentAt` DATETIME(3) NULL,
    ADD COLUMN `phoneVerifiedAt` DATETIME(3) NULL;
