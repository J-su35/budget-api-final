import { IsNotEmpty, IsNumber, IsOptional, IsString, ValidationArguments } from "class-validator";

const isNumberMessage = (validationArguments: ValidationArguments): string => {
    return `${validationArguments.property}: must to be number`
}

export class CreateItemDto {

    @IsString()
    @IsNotEmpty()
    title: string;

    @IsNumber({}, { message: isNumberMessage })
    @IsNotEmpty()
    amount: number;

    @IsNumber({}, { message: isNumberMessage })
    @IsNotEmpty()
    price: number;

    @IsOptional()
    contactMobileNo: string;
}
