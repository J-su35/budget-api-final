import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

export enum ItemStatus {
    PENDING = 'PENDING', APPROVED = 'APPROVED', REJECTED = 'REJECTED'
}

@Entity()
export class Item {
    
    @PrimaryGeneratedColumn()
    id: number;
    
    @Column()
    title: string;

    @Column()
    amount: number;

    @Column()
    price: number;

    @Column({
        nullable: true
    })
    contactMobileNo: string;

    @Column({
        nullable: false,
        default: ItemStatus.PENDING
    })
    status: ItemStatus
}
