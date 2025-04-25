-- CreateTable
CREATE TABLE `AuthOauthprovider` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NULL,

    UNIQUE INDEX `AuthOauthprovider_name_key`(`name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AuthUseridentity` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `uuid` CHAR(36) NOT NULL,
    `userId` INTEGER NOT NULL,
    `providerId` INTEGER NOT NULL,
    `providerUserId` VARCHAR(255) NOT NULL,
    `accessToken` TEXT NULL,
    `refreshToken` TEXT NULL,
    `tokenExpiresAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NULL,

    UNIQUE INDEX `AuthUseridentity_userId_providerId_key`(`userId`, `providerId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `AuthUseridentity` ADD CONSTRAINT `AuthUseridentity_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AuthUseridentity` ADD CONSTRAINT `AuthUseridentity_providerId_fkey` FOREIGN KEY (`providerId`) REFERENCES `AuthOauthprovider`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
