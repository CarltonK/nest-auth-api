-- AlterTable
ALTER TABLE `User` ADD COLUMN `passwordResetSentAt` DATETIME(3) NULL,
    ADD COLUMN `passwordResetToken` VARCHAR(191) NULL;
