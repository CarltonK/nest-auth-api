-- AlterTable
ALTER TABLE `AuthToken` ADD COLUMN `metadata` JSON NULL,
    ADD COLUMN `revoked` BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE `Session` ADD COLUMN `isActive` BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN `lastActivityAt` DATETIME(3) NULL;
